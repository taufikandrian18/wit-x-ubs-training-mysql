package authentication

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/gomodule/redigo/redis"
	"github.com/rs/xid"
	"gitlab.com/wit-id/test-mysql/common"
)

type repository struct {
	DBAuthentication *sql.DB
	DBMedia          *sql.DB
	Redis            *redis.Pool
}

func newRepository(dbAuth *sql.DB, redis *redis.Pool) *repository {

	return &repository{
		DBAuthentication: dbAuth,
		Redis:            redis,
	}
}

func (r *repository) CreateRegistration(otp Registration) (id int64, err error) {

	qb := sq.Insert("Registration").Columns(
		"OTPCode",
		"Secret",
		"Status",
		"Email",
		"Name",
		"password",
		"PhoneNumber",
		"TimeExpired",
		"TimeCreated").Values(
		otp.OTPCode,
		otp.Secret,
		"unverified",
		otp.Email,
		otp.Name,
		otp.Password,
		otp.PhoneNumber,
		otp.TimeExpired,
		time.Now())

	result, err := qb.RunWith(r.DBAuthentication).Exec()
	if err != nil {
		log.Println(err)
		return
	}

	id, err = result.LastInsertId()
	if err != nil {
		log.Println(err)
		return
	}

	return
}

func (r *repository) UpdateRegistration(otp Registration) (err error) {

	qb := sq.Update("Registration").
		Set("status", otp.Status).
		Set("time_updated", time.Now())

	_, err = qb.RunWith(r.DBAuthentication).Exec()
	if err != nil {
		log.Println(err)
		return
	}

	return
}

func (r *repository) ReadRegistration(id int64, secret, email string) (authentication []Registration,
	err error) {

	qb := sq.Select(
		"RegistrationID",
		"OTPCode",
		"Secret",
		"Status",
		"Email",
		"Name",
		"Password",
		"PhoneNumber",
		"TimeExpired").
		From("Registration")

	if id != 0 {
		qb = qb.Where("RegistrationID = ?", id)
	}

	if secret != "" {
		qb = qb.Where("Password = ?", secret)
	}

	if email != "" {
		qb = qb.Where("Email = ?", email)
	}

	rows, errQuery := qb.RunWith(r.DBAuthentication).Query()
	if errQuery != nil {
		log.Println("err query : ", errQuery)
		err = errQuery
		return
	}

	defer rows.Close()

	for rows.Next() {

		var (
			e = Registration{}
		)

		errScan := rows.Scan(
			&e.RegistrationID,
			&e.OTPCode,
			&e.Secret,
			&e.Status,
			&e.Email,
			&e.Name,
			&e.Password,
			&e.PhoneNumber,
			&e.TimeExpired)

		if errScan != nil {
			log.Println("err Scan : ", errScan)
			err = errScan
			continue
		}

		authentication = append(authentication, e)
	}

	return
}

func (r *repository) CheckAccountExists(email string, telephone string) (isExist bool, err error) {

	var (
		querySocialAuth = fmt.Sprintf("SELECT Email FROM Profile WHERE Email = '%s' || Telepon = '%s' ", email, telephone)
		query           = fmt.Sprintf("SELECT exists (%s)", querySocialAuth)
	)

	row := r.DBMedia.QueryRow(query)
	errScan := row.Scan(&isExist)

	if errScan != nil {
		log.Println("err Scan : ", errScan)
		err = errScan
		return
	}

	return

}

func (r *repository) CreateUser(reg Authentication) (profileID int64, err error) {

	var username string

	if reg.Email == "" {
		genUnique := xid.New()
		username = genUnique.String()
	} else {
		username = common.Strstr(reg.Email, "@", true)
	}

	qb := sq.Insert("Profile").Columns(
		"Username",
		"NamaLengkap",
		"Email",
		"UserPassword",
		"Telepon",
		"IDRole",
		"IsVerified").Values(
		username,
		reg.Name,
		reg.Email,
		reg.Password,
		reg.PhoneNumber,
		5,
		false)

	result, err := qb.RunWith(r.DBMedia).Exec()
	if err != nil {
		log.Println(err)
		return
	}

	profileID, err = result.LastInsertId()
	if err != nil {
		log.Println(err)
		return
	}

	return
}

func (r *repository) ReadUser(userID int64, email string) (profile []Profile, err error) {

	qb := sq.Select(
		"Profile.ProfileID",
		"Profile.Username",
		"Profile.NamaLengkap",
		"Profile.Email",
		"Profile.Telepon",
		"Profile.IDRole",
		"Profile.IsBanned",
		"Profile.IsVerified",
		"Profile.UserPassword").From("Profile")

	if userID != 0 {
		qb = qb.Where("Profile.ProfileID = ?", userID)
	}

	if email != "" {
		qb = qb.Where("Profile.Email = ?", email)
	}

	x, _, _ := qb.ToSql()
	log.Println(x)

	rows, errQuery := qb.RunWith(r.DBMedia).Query()
	if errQuery != nil {
		log.Println("err query : ", errQuery)
		err = errQuery
		return
	}

	defer rows.Close()

	for rows.Next() {

		var (
			p            = Profile{}
			passwordNull = sql.NullString{}
			usernameNull = sql.NullString{}
			phoneNull    = sql.NullString{}
		)

		errScan := rows.Scan(
			&p.ProfileID,
			&usernameNull,
			&p.NamaLengkap,
			&p.Email,
			&phoneNull,
			&p.IDRole,
			&p.Role,
			&p.IsBanned,
			&p.IsVerified,
			&passwordNull)

		if errScan != nil {
			log.Println("err Scan : ", errScan)
			err = errScan
			continue
		}

		p.UserPassword = passwordNull.String
		p.Username = usernameNull.String
		p.Telepon = phoneNull.String

		profile = append(profile, p)
	}

	return
}

func (r *repository) UpdatePassword(userID int64, password string) (err error) {

	queryBuilder := sq.Update("Registration").
		Set("Password", password).
		Where("RegistrationID = ?", userID)

	_, err = queryBuilder.RunWith(r.DBMedia).Exec()
	if err != nil {
		log.Println(err)
		return
	}

	return
}

func (r *repository) CreateForgot(fg Registration) (id int64, err error) {

	qb := sq.Insert("forgot_password").Columns(
		"otp_code",
		"secret",
		"status",
		"email",
		"user_id",
		"time_expired",
		"time_created").Values(
		fg.OTPCode,
		fg.Secret,
		fg.Status,
		fg.Email,
		fg.TimeExpired,
		time.Now())

	result, err := qb.RunWith(r.DBAuthentication).Exec()
	if err != nil {
		log.Println(err)
		return
	}

	id, err = result.LastInsertId()
	if err != nil {
		log.Println(err)
		return
	}

	return
}

func (r *repository) UpdateForgot(fg Registration) (err error) {

	qb := sq.Update("forgot_password").
		Set("status", fg.Status).
		Set("time_updated", time.Now()).
		Where("id = ?", fg.RegistrationID)

	_, err = qb.RunWith(r.DBAuthentication).Exec()
	if err != nil {
		log.Println(err)
		return
	}

	return
}

func (r *repository) ReadForgot(id, userID int64, secret, email string) (s []Registration, err error) {

	qb := sq.Select(
		"id",
		"otp_code",
		"secret",
		"status",
		"email",
		"time_expired").
		From("forgot_password")

	if id != 0 {
		qb = qb.Where("id = ?", id)
	}

	if userID != 0 {
		qb = qb.Where("user_id = ?", userID)
	}

	if secret != "" {
		qb = qb.Where("secret = ?", secret)
	}

	if email != "" {
		qb = qb.Where("email = ?", email)
	}

	rows, errQuery := qb.RunWith(r.DBAuthentication).Query()
	if errQuery != nil {
		log.Println("err query : ", errQuery)
		err = errQuery
		return
	}

	defer rows.Close()

	for rows.Next() {

		var (
			e = Registration{}
		)

		errScan := rows.Scan(
			&e.RegistrationID,
			&e.OTPCode,
			&e.Secret,
			&e.Status,
			&e.Email,
			&e.TimeExpired)

		if errScan != nil {
			log.Println("err Scan : ", errScan)
			err = errScan
			continue
		}

		s = append(s, e)
	}

	return
}

func (r *repository) CreateSocialIdentity(identity SocialIdentity) (err error) {

	qb := sq.Insert("identity").Columns(
		"id",
		"provider",
		"name",
		"email",
		"time_created").Values(
		identity.ID,
		identity.Provider,
		identity.Name,
		identity.Email,
		time.Now())

	result, err := qb.RunWith(r.DBAuthentication).Exec()
	if err != nil {
		log.Println(err)
		return
	}

	_, err = result.LastInsertId()
	if err != nil {
		log.Println(err)
		return
	}

	return
}

func (r *repository) UpdateSocialIdentity(identity SocialIdentity) (err error) {

	qb := sq.Update("identity").
		Set("name", identity.Name).
		Set("email", identity.Email).
		Set("profile_id", identity.Profile.ProfileID).
		Set("time_updated", time.Now()).
		Where("id = ?", identity.ID)

	_, err = qb.RunWith(r.DBAuthentication).Exec()
	if err != nil {
		log.Println(err)
		return
	}

	return
}

func (r *repository) ReadSocialIdentity(id, email string) (social []SocialIdentity, err error) {

	qb := sq.Select(
		"id",
		"name",
		"email",
		"profile_id",
		"provider").
		From("identity")

	if id != "" {
		qb = qb.Where("id = ?", id)
	}

	if email != "" {
		qb = qb.Where("email = ?", email)
	}

	rows, errQuery := qb.RunWith(r.DBAuthentication).Query()
	if errQuery != nil {
		log.Println("err query : ", errQuery)
		err = errQuery
		return
	}

	defer rows.Close()

	for rows.Next() {

		var (
			s           = SocialIdentity{}
			profileNull = sql.NullInt64{}
		)

		errScan := rows.Scan(
			&s.ID,
			&s.Name,
			&s.Email,
			&profileNull,
			&s.Provider)

		if errScan != nil {
			log.Println("err Scan : ", errScan)
			err = errScan
			continue
		}

		s.Profile.ProfileID = profileNull.Int64

		social = append(social, s)
	}

	return
}
