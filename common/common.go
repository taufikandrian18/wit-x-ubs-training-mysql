package common

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gomodule/redigo/redis"
)

const (
	ResponseUnauthorized        = "unauthorized access"
	ResponseContentNotFound     = "content not found"
	ResponseForbidden           = "forbidden"
	ResponseOK                  = "ok"
	ResponseBadRequest          = "bad request"
	ResponseMethodNotAllowed    = "method not allowed"
	ResponseInternalServerError = "internal server error"

	ResponseEmailFormat           = "invalid mail format"
	ResponsePasswordLength        = "password minimum 8 character"
	ResponsePasswordFormat        = "password has to contain letter and number"
	ResponsePasswordDivergent     = "password is different from confirmation"
	ResponsePhoneNumberLetter     = "phone number cannot contain letter"
	ResponsePhoneNumberTooShort   = "phone number too short"
	ResponsePhoneNumberTooLong    = "phone number too long"
	ResponeNameFormat             = "name can only contain letter"
	ResponeNameTooShort           = "name too short"
	ResponseAuthenticationInvalid = "invalid authentication"
	ResponseUpdatePasswordFailed  = "update password failed"
	ResponseInvalidOTP            = "invalid otp"
	ResponseVerificationMailSent  = "verification mail sent"
	ResponseSessionExpired        = "session expired"
	ResponseInvalidSource         = "invalid source"
	ResponseInvalidType           = "invalid type"

	SubjectRegister       = "Verify Registration"
	SubjectForgotPassword = "Verify Forgot Password"

	SourceTypeWebsite = "website"
	SourceTypeAndroid = "android"
	SourceTypeIOS     = "ios"

	AppName         = "UBS Training Apps"
	JwtSignatureKey = "Edson Arantes do Nascimento"

	RequestTypeChangePassword = "change"
	RequestTypeForgotPassword = "forgot"
	RequestTypeRegistration   = "register"

	TimeLayout    = "2006-01-02"
	TimeLayoutHMS = "2006-01-02 15:04:05"

	AccessReadQuran   = "read_quran"
	AccessReadShalat  = "read_shalat"
	AccessReadMosque  = "read_mosque"
	AccessReadArticle = "read_article"
	AccessReadAgenda  = "read_agenda"
	AccessReadVideo   = "read_video"

	StatusForgotPasswordChanged    = "password_changed"
	StatusForgotPasswordUnverified = "unverified"
	StatusForgotPasswordVerified   = "verified"
)

func TimeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	log.Printf(`{"type":"process_time", "function": "%s", "time":"%.0f"}`, name, elapsed.Seconds()*float64(1000))
}

func InitDB(connection string) (db *sql.DB, err error) {

	db, err = sql.Open("mysql", connection)
	if err != nil {
		log.Fatalf("Could not open db: %v \nwith connection %s", err, connection)
	}
	err = db.PingContext(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	return
}

func InitRedis(connection, auth string) *redis.Pool {
	return &redis.Pool{
		MaxIdle:   80,
		MaxActive: 12000,
		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial("tcp", connection)
			if err != nil {
				log.Fatalln(err.Error())
			}

			if os.Getenv("OPEN_API_ENV") != "local" {
				_, err = c.Do("AUTH", auth)
				if err != nil {
					c.Close()
					log.Fatalln(err.Error())
				}
			}

			return c, err
		},
	}
}

func InitDBV2(connection string) (db *sql.DB, err error) {

	fmt.Println("TEST CONNECTION : ", connection)
	db, err = sql.Open("mysql", connection)
	if err != nil {
		log.Fatalf("Could not open db: %v \nwith connection %s", err, connection)
	}
	err = db.PingContext(context.Background())
	if err != nil {
		fmt.Println("TEST err : ", err)
		log.Fatal(err)
	}

	return
}

func InitRedisV2(connection, auth string) *redis.Pool {
	return &redis.Pool{
		MaxIdle:   80,
		MaxActive: 12000,
		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial("tcp", connection)
			if err != nil {
				log.Fatalln(err.Error())
			}

			if os.Getenv("OPEN_API_ENV") != "local" {
				_, err = c.Do("AUTH", auth)
				if err != nil {
					c.Close()
					log.Fatalln(err.Error())
				}
			}

			return c, err
		},
	}
}
