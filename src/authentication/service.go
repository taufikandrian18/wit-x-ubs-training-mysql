package authentication

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/joho/godotenv"
	"github.com/xlzd/gotp"
	"gitlab.com/wit-id/test-mysql/common"
)

type service struct {
	repository *repository
}

type Agent interface {
	Register(email, name, phone, password string) (
		otp Registration, err error)
	Verify(payload, otp, source, requestType string) (
		profile Profile, err error)
	Login(email, password string) (profile Registration,
		err error)
	UpdatePassword(userID int64, requestType, oldPassword,
		newPassword string) (token string, err error)
	CheckV3PasswordFilled(userID int64) (filled bool,
		err error)
	ForgotPassword(email string) (encryptedPayload string,
		err error)
	ResendMail(requestType, payload string) (err error)
	SocialDataCompletition(id, name, email, password, phone string) (profile Profile, err error)
	GetUserByID(userID int64) (profile Profile, err error)
}

func NewService() Agent {

	godotenv.Load()

	var (
		dbConnAuth = os.Getenv("DB_CONNECTION_AUTH")
		redisConn  = os.Getenv("REDIS_CONNECTION")
		redisAuth  = os.Getenv("REDIS_AUTH")
	)

	dbAuth, err := common.InitDBV2(dbConnAuth)
	if err != nil {
		log.Fatalln(err)
	}

	redis := common.InitRedisV2(redisConn, redisAuth)
	repo := newRepository(dbAuth, redis)
	return &service{
		repository: repo,
	}

}

func (s *service) Register(email, name, phone, password string) (otp Registration, err error) {

	secret := gotp.RandomSecret(16)

	totp := gotp.NewTOTP(secret, 6, 1, nil)

	otpCode := totp.Now()

	ciphertext, err := s.encrypt([]byte(password), keyphrase)
	if err != nil {
		log.Println(err)
		return
	}

	encodedPassword := make([]byte, hex.EncodedLen(len(ciphertext)))
	hex.Encode(encodedPassword, ciphertext)

	otp = Registration{
		OTPCode:     otpCode,
		TimeExpired: time.Now().Add(time.Hour * time.Duration(1)),
	}

	_, err = s.repository.CreateRegistration(otp)
	if err != nil {
		log.Println(err.Error())
		err = fmt.Errorf("failed to generate otp")
		return
	}

	return
}

func (s *service) Login(email, password string) (profile Registration,
	err error) {

	src := []byte(password)
	dst := make([]byte, hex.DecodedLen(len(src)))
	n, err := hex.Decode(dst, src)
	if err != nil {
		log.Fatal(err)
	}

	decryptedInput, err := s.decrypt(dst[:n], keyphrase)
	if err != nil {
		log.Println(err)
		return
	}

	storedPass := fmt.Sprintf("%s", decryptedInput)

	p, err := s.repository.ReadRegistration(0, storedPass, email)
	if err != nil {
		log.Println(err)
		err = fmt.Errorf(common.ResponseAuthenticationInvalid)
		return
	}

	token, err := s.generateToken(p[0].RegistrationID, p[0].Email, p[0].Password)
	if err != nil {
		log.Println(err)
		return
	}

	profile.Token = token

	return
}

func (s *service) Verify(payload, otp, source, requestType string) (
	profile Profile, err error) {

	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		fmt.Println("decode error:", err)
		return
	}

	plain, err := s.decrypt(decoded, keyphrase)
	if err != nil {
		log.Println(err)
		return
	}

	payloadConfig := strings.Split(fmt.Sprintf("%s", plain), "|")

	secret := payloadConfig[0]
	email := payloadConfig[1]

	var (
		userID  int64
		account []Registration
	)

	switch requestType {
	case common.RequestTypeRegistration:
		account, err = s.repository.ReadRegistration(0, secret, email)
		if err != nil {
			log.Println(err)
			err = fmt.Errorf("user not found")
			return
		}

		now := time.Now().Unix()

		if account[0].TimeExpired.Unix() < now {
			err = fmt.Errorf("session expired")
			return
		}

		if account[0].OTPCode != otp {
			err = fmt.Errorf(common.ResponseInvalidOTP)
			return
		}

		account[0].Status = "verified"
		err = s.repository.UpdateRegistration(account[0])
		if err != nil {
			log.Println(err)
			return
		}

		// userID, err = s.repository.CreateUser(account[0].Auth)
		// if err != nil {
		// 	log.Println(err)
		// 	return
		// }

	case common.RequestTypeForgotPassword:

		account, err = s.repository.ReadForgot(0, 0, secret, email)
		if err != nil {
			log.Println(err)
			err = fmt.Errorf("user not found")
			return
		}

		now := time.Now().Unix()

		if account[0].TimeExpired.Unix() < now {
			err = fmt.Errorf("session expired")
			return
		}

		if account[0].OTPCode != otp {
			err = fmt.Errorf(common.ResponseInvalidOTP)
			return
		}

		account[0].Status = common.StatusForgotPasswordVerified

		err = s.repository.UpdateForgot(account[0])
		if err != nil {
			log.Println(err)
			return
		}
	}

	p, err := s.repository.ReadUser(userID, "")
	if err != nil {
		log.Println(err)
		return
	}

	token, err := s.generateToken(userID, "5", "0")
	if err != nil {
		log.Println(err)
		return
	}

	profile = p[0]
	profile.Token = token

	return
}

func (s *service) UpdatePassword(userID int64, requestType, oldPassword,
	newPassword string) (token string, err error) {

	p, err := s.repository.ReadRegistration(userID, "", "")
	if err != nil {
		log.Println(err)
		err = fmt.Errorf(common.ResponseAuthenticationInvalid)
		return
	}

	switch requestType {
	case common.RequestTypeChangePassword:
		token, err = s.changePassword(p, oldPassword, newPassword)
		if err != nil {
			log.Println(err)
			err = fmt.Errorf(common.ResponseUpdatePasswordFailed)
			return
		}
	case common.RequestTypeForgotPassword:
		token, err = s.replacePassword(p, newPassword)
		if err != nil {
			log.Println(err)
			err = fmt.Errorf(common.ResponseUpdatePasswordFailed)
			return
		}
	default:
		err = fmt.Errorf("invalid")
	}

	return
}

func (s *service) ForgotPassword(email string) (encryptedPayload string,
	err error) {

	secret := gotp.RandomSecret(16)

	totp := gotp.NewTOTP(secret, 6, 1, nil)

	otpCode := totp.Now()

	_, err = s.repository.ReadRegistration(0, "", email)
	if err != nil {
		log.Println(err)
		return
	}

	fg := Registration{
		OTPCode:     otpCode,
		TimeExpired: time.Now().Add(time.Hour * time.Duration(1)),
	}

	fgID, err := s.repository.CreateForgot(fg)
	if err != nil {
		log.Println(err)
		return
	}

	fg.RegistrationID = fgID
	fg.TimeCreated = time.Now()

	payload, err := s.encrypt([]byte(secret+"|"+fg.Email), keyphrase)
	if err != nil {
		log.Println(err)
		return
	}

	err = s.repository.UpdateForgot(fg)
	if err != nil {
		log.Println(err)
		return
	}

	encryptedPayload = base64.StdEncoding.EncodeToString(payload)

	if os.Getenv("AUTH_ENV") == "local" {
		log.Printf("OTP : %s", otpCode)
		log.Printf("PAYLOAD : %s", encryptedPayload)
	}

	return
}

func (s *service) CheckV3PasswordFilled(userID int64) (filled bool,
	err error) {

	p, err := s.repository.ReadUser(userID, "")
	if err != nil {
		log.Println(err)
		err = fmt.Errorf(common.ResponseAuthenticationInvalid)
		return
	}

	if p[0].UserPassword != "" {
		filled = true
		return
	}

	return
}

func (s *service) ResendMail(requestType, payload string) (err error) {

	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		fmt.Println("decode error:", err)
		return
	}

	plain, err := s.decrypt(decoded, keyphrase)
	if err != nil {
		log.Println(err)
		return
	}

	payloadConfig := strings.Split(fmt.Sprintf("%s", plain), "|")

	secret := payloadConfig[0]
	email := payloadConfig[1]

	var (
		account []Registration
	)

	switch requestType {
	case common.RequestTypeRegistration:
		account, err = s.repository.ReadRegistration(0, secret, email)
		if err != nil {
			log.Println(err)
			return
		}
	case common.RequestTypeForgotPassword:
		account, err = s.repository.ReadForgot(0, 0, secret, email)
		if err != nil {
			log.Println(err)
			return
		}
	default:
		err = fmt.Errorf("invalid")
		return
	}

	now := time.Now().Unix()

	if account[0].TimeExpired.Unix() < now {
		err = fmt.Errorf("session expired")
		return
	}

	err = s.repository.UpdateRegistration(account[0])
	if err != nil {
		log.Println(err)
		return
	}

	return
}

func (s *service) SocialDataCompletition(id, name, email, password, phone string) (profile Profile, err error) {

	social, err := s.repository.ReadSocialIdentity(id, "")
	if err != nil || len(social) < 1 {
		log.Println(err)
		return
	}

	ciphertext, err := s.encrypt([]byte(password), keyphrase)
	if err != nil {
		log.Println(err)
		return
	}

	encodedPassword := make([]byte, hex.EncodedLen(len(ciphertext)))
	hex.Encode(encodedPassword, ciphertext)

	reg := Authentication{
		Name:        name,
		Email:       email,
		Password:    fmt.Sprintf("%s", encodedPassword),
		PhoneNumber: phone,
	}

	var (
		p         []Profile
		profileID int64
		identity  []SocialIdentity
	)

	p, err = s.repository.ReadUser(0, email)
	if err != nil {
		log.Println(err)
	}

	if len(p) < 1 {
		profileID, err = s.repository.CreateUser(reg)
		if err != nil {
			log.Println(err)
		}

		p, err = s.repository.ReadUser(profileID, "")
		if err != nil {
			log.Println(err)
			return
		}

		identity, err = s.repository.ReadSocialIdentity(id, "")
		if err != nil {
			log.Println(err)
			return
		}

		identity[0].Profile.ProfileID = profileID

		err = s.repository.UpdateSocialIdentity(identity[0])
	}

	token, err := s.generateToken(profileID, "5", "0")
	if err != nil {
		log.Println(err)
		return
	}

	profile = p[0]
	profile.Token = token

	return
}

func (s *service) changePassword(p []Registration, oldPassword,
	newPassword string) (token string, err error) {

	src := []byte(p[0].Password)
	dst := make([]byte, hex.DecodedLen(len(src)))
	n, err := hex.Decode(dst, src)
	if err != nil {
		log.Fatal(err)
	}

	decryptedInput, err := s.decrypt(dst[:n], keyphrase)
	if err != nil {
		log.Println(err)
		return
	}

	storedPass := fmt.Sprintf("%s", decryptedInput)

	if storedPass != oldPassword {
		err = fmt.Errorf(common.ResponseAuthenticationInvalid)
		return
	}

	ciphertext, err := s.encrypt([]byte(newPassword), keyphrase)
	if err != nil {
		log.Println(err)
		return
	}

	encodedPassword := make([]byte, hex.EncodedLen(len(ciphertext)))
	hex.Encode(encodedPassword, ciphertext)

	p[0].Password = fmt.Sprintf("%s", encodedPassword)

	err = s.repository.UpdatePassword(p[0].RegistrationID, p[0].Password)
	if err != nil {
		log.Println(err)
		return
	}

	token, err = s.generateToken(p[0].RegistrationID, p[0].Email, p[0].Password)
	if err != nil {
		log.Println(err)
		err = fmt.Errorf(common.ResponseUpdatePasswordFailed)
		return
	}

	return
}

func (s *service) replacePassword(p []Registration, password string) (token string,
	err error) {

	ciphertext, err := s.encrypt([]byte(password), keyphrase)
	if err != nil {
		log.Println(err)
		return
	}

	encodedPassword := make([]byte, hex.EncodedLen(len(ciphertext)))
	hex.Encode(encodedPassword, ciphertext)

	p[0].Password = fmt.Sprintf("%s", encodedPassword)

	err = s.repository.UpdatePassword(p[0].RegistrationID, p[0].Password)
	if err != nil {
		log.Println(err)
		return
	}

	token, err = s.generateToken(p[0].RegistrationID, p[0].Email, p[0].Password)
	if err != nil {
		log.Println(err)
		err = fmt.Errorf(common.ResponseUpdatePasswordFailed)
		return
	}

	return
}

func (s *service) createHash(key string) (hash string) {
	hasher := md5.New()
	hasher.Write([]byte(key))
	hash = hex.EncodeToString(hasher.Sum(nil))
	return
}

func (s *service) encrypt(data []byte, passphrase string) (
	ciphered []byte, err error) {
	block, _ := aes.NewCipher([]byte(s.createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println(err)
		return
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		log.Println(err)
		return
	}
	ciphered = gcm.Seal(nonce, nonce, data, nil)
	return
}

func (s *service) decrypt(data []byte, passphrase string) (
	plain []byte, err error) {
	key := []byte(s.createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println(err)
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println(err)
		return
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plain, err = gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Println(err)
		return
	}
	return
}

func (s *service) generateToken(userID int64, roleID, isVerified string) (
	signedToken string, err error) {

	claims := UserAuthClaims{
		RegistrationID: userID,
		Email:          roleID,
		Password:       isVerified,
		StandardClaims: jwt.StandardClaims{
			Issuer:    common.AppName,
			ExpiresAt: time.Now().Add(time.Duration(8760) * time.Hour).Unix(),
		},
	}

	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		claims,
	)

	signedToken, err = token.SignedString([]byte(common.JwtSignatureKey))

	return
}

func (s *service) GetUserByID(userID int64) (profile Profile, err error) {

	p, err := s.repository.ReadUser(userID, "")
	if err != nil {
		log.Println(err)
		err = fmt.Errorf(common.ResponseAuthenticationInvalid)
		return
	}

	profile = p[0]

	return
}
