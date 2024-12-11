package healthcheck

import (
	"net/http"

	"gitlab.com/wit-id/test-mysql/common"
)

func HealthCheck(w http.ResponseWriter, r *http.Request) {
	common.HTTPResponse(w, http.StatusOK, nil, nil, nil)
}
