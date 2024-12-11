package authentication

import (
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

type Authentication struct {
	AuthenticationID     int64  `json:"authentication_id"`
	ProfileID            int64  `json:"profile_id"`
	Secret               string `json:"secret"`
	Status               string `json:"status"`
	Email                string `json:"email"`
	Name                 string `json:"name"`
	OldPassword          string `json:"old_password,omitempty"`
	Password             string `json:"password"`
	PasswordConfirmation string `json:"password_confirmation,omitempty"`
	PhoneNumber          string `json:"phone_number"`
	RequestType          string `json:"type,omitempty"`
}

type Registration struct {
	RegistrationID int64     `json:"registration_id"` // Corresponds to AUTO_INCREMENT primary key
	OTPCode        string    `json:"otp_code"`        // VARCHAR(255), NOT NULL
	Secret         string    `json:"secret"`          // VARCHAR(255), NOT NULL
	Status         string    `json:"status"`          // VARCHAR(50), DEFAULT 'unverified'
	Email          string    `json:"email"`           // VARCHAR(255), NOT NULL
	Name           string    `json:"name"`            // VARCHAR(255), NOT NULL
	Password       string    `json:"password"`        // VARCHAR(255), NOT NULL
	PhoneNumber    string    `json:"phone_number"`    // VARCHAR(50), NOT NULL
	TimeExpired    time.Time `json:"time_expired"`    // DATETIME, NOT NULL
	TimeCreated    time.Time `json:"time_created"`    // DATETIME, DEFAULT CURRENT_TIMESTAMP
	Token          string    `json:"token"`
}

type SocialIdentity struct {
	ID                   string  `json:"id"`
	Name                 string  `json:"name"`
	Email                string  `json:"email"`
	Provider             string  `json:"provider"`
	Password             string  `json:"password,omitempty"`
	PasswordConfirmation string  `json:"password_confirmation,omitempty"`
	PhoneNumber          string  `json:"phone_number,omitempty"`
	SocialToken          string  `json:"social_token,omitempty"`
	Profile              Profile `json:"profile,omitempty"`
}

type Profile struct {
	ProfileID    int64  `json:"id_profil"`
	Username     string `json:"username"`
	NamaLengkap  string `json:"nama_lengkap"`
	Email        string `json:"email"`
	Telepon      string `json:"telepon"`
	IDRole       int64  `json:"id_role"`
	Role         string `json:"role"`
	UserPassword string `json:"user_password"`
	IsVerified   int    `json:"verified_user"`
	IsBanned     int    `json:"is_banned"`
	Token        string `json:"token"`
}

type UserAuthClaims struct {
	RegistrationID int64  `json:"registration_id"`
	Email          string `json:"email"`
	Password       string `json:"password"`
	jwt.StandardClaims
}
