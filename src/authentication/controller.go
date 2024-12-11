package authentication

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/miguelpragier/handy"
	"gitlab.com/wit-id/test-mysql/common"
)

func Register(w http.ResponseWriter, r *http.Request) {
	defer common.TimeTrack(time.Now(), "authenticationV3.Register")

	common.CorsHandler(&w, r)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != http.MethodPost {
		common.HTTPResponse(w, http.StatusMethodNotAllowed,
			nil, nil, common.ResponseMethodNotAllowed)
		return
	}

	var a Authentication
	json.NewDecoder(r.Body).Decode(&a)

	if !handy.CheckEmail(a.Email) || !strings.Contains(a.Email, ".") {
		common.HTTPResponse(w, http.StatusBadRequest,
			common.ResponseEmailFormat, nil, common.ResponseBadRequest)
		return
	}

	passwordValidation := handy.CheckNewPassword(a.Password, a.PasswordConfirmation,
		8, handy.CheckNewPasswordComplexityRequireNumber)

	switch passwordValidation {
	case handy.CheckNewPasswordResultDivergent:
		common.HTTPResponse(w, http.StatusBadRequest,
			common.ResponsePasswordDivergent, nil, common.ResponseBadRequest)
		return
	case handy.CheckNewPasswordResultTooShort:
		common.HTTPResponse(w, http.StatusBadRequest,
			common.ResponsePasswordLength, nil, common.ResponseBadRequest)
		return
	case handy.CheckNewPasswordResultTooSimple:
		common.HTTPResponse(w, http.StatusBadRequest,
			common.ResponsePasswordFormat, nil, common.ResponseBadRequest)
		return
	}

	if handy.HasLetter(a.PhoneNumber) {
		common.HTTPResponse(w, http.StatusBadRequest,
			common.ResponsePhoneNumberLetter, nil, common.ResponseBadRequest)
		return
	}

	if !handy.CheckMinLen(a.PhoneNumber, int(8)) {
		common.HTTPResponse(w, http.StatusBadRequest,
			common.ResponsePhoneNumberTooShort, nil, common.ResponseBadRequest)
		return
	}

	if len(a.PhoneNumber) > 20 {
		common.HTTPResponse(w, http.StatusBadRequest,
			common.ResponsePhoneNumberTooLong, nil, common.ResponseBadRequest)
		return
	}

	prefixed, err := common.PhoneNumberPrefix(a.PhoneNumber)
	if err != nil {
		common.HTTPResponse(w, http.StatusBadRequest,
			err.Error(), nil, common.ResponseBadRequest)
		return
	}

	a.PhoneNumber = prefixed

	spaceCheck := handy.CleanSpaces(a.Name)
	if spaceCheck == "" {
		common.HTTPResponse(w, http.StatusBadRequest,
			common.ResponeNameFormat, nil, common.ResponseBadRequest)
	}

	if len(a.Name) < 3 {
		common.HTTPResponse(w, http.StatusBadRequest,
			common.ResponeNameTooShort, nil, common.ResponseBadRequest)
		return
	}

	nameValidation := handy.CheckPersonName(a.Name, false)
	switch nameValidation {
	case handy.CheckPersonNameResultPolluted:
		common.HTTPResponse(w, http.StatusBadRequest,
			common.ResponeNameFormat, nil, common.ResponseBadRequest)
		return
	}

	fmt.Println("nameValidation")

	_, err = agent.Register(a.Email, a.Name, a.PhoneNumber, a.Password)
	if err != nil {
		common.HTTPResponse(w, http.StatusBadRequest,
			err.Error(), nil, common.ResponseBadRequest)
		return
	}

	common.HTTPResponse(w, http.StatusOK, common.ResponseVerificationMailSent, nil, nil)
}

func Login(w http.ResponseWriter, r *http.Request) {
	defer common.TimeTrack(time.Now(), "authenticationV3.Login")

	common.CorsHandler(&w, r)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != http.MethodPost {
		common.HTTPResponse(w, http.StatusMethodNotAllowed,
			nil, nil, common.ResponseMethodNotAllowed)
		return
	}

	var a Authentication
	json.NewDecoder(r.Body).Decode(&a)

	if !handy.CheckEmail(a.Email) || !strings.Contains(a.Email, ".") {
		common.HTTPResponse(w, http.StatusBadRequest,
			common.ResponseEmailFormat, nil, common.ResponseBadRequest)
		return
	}

	data, err := agent.Login(a.Email, a.Password)
	if err != nil {
		common.HTTPResponse(w, http.StatusBadRequest,
			err.Error(), nil, common.ResponseBadRequest)
		return
	}

	common.HTTPResponse(w, http.StatusOK, data, nil, nil)

}

func Verify(w http.ResponseWriter, r *http.Request) {
	defer common.TimeTrack(time.Now(), "authenticationV3.Verify")

	common.CorsHandler(&w, r)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != http.MethodGet {
		common.HTTPResponse(w, http.StatusMethodNotAllowed,
			nil, nil, common.ResponseMethodNotAllowed)
		return
	}

	payload := r.URL.Query().Get("payload")
	otp := r.URL.Query().Get("otp")
	source := r.URL.Query().Get("source")

	if !(source == common.SourceTypeWebsite ||
		source == common.SourceTypeAndroid ||
		source == common.SourceTypeIOS) {
		common.HTTPResponse(w, http.StatusBadRequest,
			common.ResponseInvalidSource, nil, common.ResponseBadRequest)
		return
	}

	requestType := r.URL.Query().Get("type")
	if !(requestType == common.RequestTypeRegistration ||
		requestType == common.RequestTypeForgotPassword) {
		common.HTTPResponse(w, http.StatusBadRequest,
			common.ResponseInvalidType, nil, common.ResponseBadRequest)
		return
	}

	data, err := agent.Verify(payload, otp, source, requestType)
	if err != nil {
		switch err.Error() {
		case common.ResponseInvalidOTP:
			common.HTTPResponse(w, http.StatusBadRequest,
				err.Error(), nil, common.ResponseBadRequest)
		case common.ResponseSessionExpired:
			common.HTTPResponse(w, http.StatusBadRequest,
				err.Error(), nil, common.ResponseBadRequest)
		default:
			common.HTTPResponse(w, http.StatusInternalServerError,
				err.Error(), nil, common.ResponseInternalServerError)
		}
		return
	}

	common.HTTPResponse(w, http.StatusOK, data, nil, nil)
}

func ChangePassword(w http.ResponseWriter, r *http.Request) {
	defer common.TimeTrack(time.Now(), "authenticationV3.ChangePassword")

	common.CorsHandler(&w, r)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != http.MethodPost {
		common.HTTPResponse(w, http.StatusMethodNotAllowed,
			nil, nil, common.ResponseMethodNotAllowed)
		return
	}

	var a Authentication
	json.NewDecoder(r.Body).Decode(&a)

	passwordValidation := handy.CheckNewPassword(a.Password, a.PasswordConfirmation,
		8, handy.CheckNewPasswordComplexityRequireNumber)

	switch passwordValidation {
	case handy.CheckNewPasswordResultDivergent:
		common.HTTPResponse(w, http.StatusBadRequest,
			common.ResponsePasswordDivergent, nil, common.ResponseBadRequest)
		return
	case handy.CheckNewPasswordResultTooShort:
		common.HTTPResponse(w, http.StatusBadRequest,
			common.ResponsePasswordLength, nil, common.ResponseBadRequest)
		return
	case handy.CheckNewPasswordResultTooSimple:
		common.HTTPResponse(w, http.StatusBadRequest,
			common.ResponsePasswordFormat, nil, common.ResponseBadRequest)
		return
	}

	data, err := agent.UpdatePassword(a.ProfileID, a.RequestType,
		a.OldPassword, a.Password)
	if err != nil {
		common.HTTPResponse(w, http.StatusInternalServerError,
			err.Error(), nil, common.ResponseInternalServerError)
		return
	}

	common.HTTPResponse(w, http.StatusOK, data, nil, nil)

}

func ForgotPassword(w http.ResponseWriter, r *http.Request) {
	defer common.TimeTrack(time.Now(), "authenticationV3.ForgotPassword")

	common.CorsHandler(&w, r)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != http.MethodPost {
		common.HTTPResponse(w, http.StatusMethodNotAllowed,
			nil, nil, common.ResponseMethodNotAllowed)
		return
	}

	var a Authentication
	json.NewDecoder(r.Body).Decode(&a)

	if !handy.CheckEmail(a.Email) || !strings.Contains(a.Email, ".") {
		common.HTTPResponse(w, http.StatusBadRequest,
			common.ResponseEmailFormat, nil, common.ResponseBadRequest)
		return
	}

	payload, err := agent.ForgotPassword(a.Email)
	if err != nil {
		common.HTTPResponse(w, http.StatusBadRequest,
			err.Error(), nil, common.ResponseBadRequest)
		return
	}

	include := make(map[string]interface{})
	include["payload"] = payload

	common.HTTPResponse(w, http.StatusOK, common.ResponseVerificationMailSent, include, nil)
}

func ResendMail(w http.ResponseWriter, r *http.Request) {
	defer common.TimeTrack(time.Now(), "authenticationV3.ResendMail")

	common.CorsHandler(&w, r)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != http.MethodPost {
		common.HTTPResponse(w, http.StatusMethodNotAllowed,
			nil, nil, common.ResponseMethodNotAllowed)
		return
	}

	var result map[string]interface{}
	json.NewDecoder(r.Body).Decode(&result)

	payload := result["payload"].(string)
	requestType := result["type"].(string)

	if payload == "" ||
		!(requestType == common.RequestTypeForgotPassword ||
			requestType == common.RequestTypeRegistration) {
		common.HTTPResponse(w, http.StatusBadRequest,
			nil, nil, "invalid params")
		return
	}

	err := agent.ResendMail(requestType, payload)
	if err != nil {
		common.HTTPResponse(w, http.StatusInternalServerError,
			nil, nil, err.Error())
		return
	}

	common.HTTPResponse(w, http.StatusOK, "mail sent", nil, nil)

}

func SocialCompletition(w http.ResponseWriter, r *http.Request) {
	defer common.TimeTrack(time.Now(), "authenticationV3.Completition")

	common.CorsHandler(&w, r)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != http.MethodPost {
		common.HTTPResponse(w, http.StatusMethodNotAllowed,
			nil, nil, common.ResponseMethodNotAllowed)
		return
	}

	var a SocialIdentity
	json.NewDecoder(r.Body).Decode(&a)

	passwordValidation := handy.CheckNewPassword(a.Password, a.PasswordConfirmation,
		8, handy.CheckNewPasswordComplexityRequireNumber)

	switch passwordValidation {
	case handy.CheckNewPasswordResultDivergent:
		common.HTTPResponse(w, http.StatusBadRequest,
			common.ResponsePasswordDivergent, nil, common.ResponseBadRequest)
		return
	case handy.CheckNewPasswordResultTooShort:
		common.HTTPResponse(w, http.StatusBadRequest,
			common.ResponsePasswordLength, nil, common.ResponseBadRequest)
		return
	case handy.CheckNewPasswordResultTooSimple:
		common.HTTPResponse(w, http.StatusBadRequest,
			common.ResponsePasswordFormat, nil, common.ResponseBadRequest)
		return
	}

	data, err := agent.SocialDataCompletition(a.ID, a.Name, a.Email,
		a.Password, a.PhoneNumber)
	if err != nil {
		common.HTTPResponse(w, http.StatusInternalServerError,
			err.Error(), nil, common.ResponseInternalServerError)
		return
	}

	common.HTTPResponse(w, http.StatusOK, data, nil, nil)
}
