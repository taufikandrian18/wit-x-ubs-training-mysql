package common

import (
	"encoding/json"
	"net/http"
)

type httpresponse struct {
	Data    interface{} `json:"data,omitempty"`
	Meta    interface{} `json:"interface,omitempty"`
	Links   interface{} `json:"links,omitempty"`
	Error   interface{} `json:"error,omitempty"`
	Include interface{} `json:"include,omitempty"`
}

func HTTPResponse(w http.ResponseWriter, status int,
	data, include, err interface{}) {
	response := httpresponse{
		Data:    data,
		Include: include,
		Error:   err,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(response)

}

func CorsHandler(w *http.ResponseWriter, req *http.Request) {
	(*w).Header().Set("Access-Control-Allow-Credentials", "true")
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	(*w).Header().Set("Access-Control-Max-Age", "3600")
}
