package authentication

import (
	"database/sql"
	"log"
	"os"

	"gitlab.com/wit-id/test-mysql/common"
)

var (
	agent     Agent
	DB        *sql.DB
	keyphrase string
	// sender    string
	// baseuri   *url.URL
)

func init() {
	log.SetFlags(log.Llongfile)
	log.Println("Authentication V3 Initializing")

	agent = NewService()

	DB, _ = common.InitDB(os.Getenv("DB_CONNECTION_AUTH"))

	// keyphrase = os.Getenv("AUTH_KEYPHRASE")
	// baseuri, _ = url.Parse(os.Getenv("AUTH_URL"))
	// sender = os.Getenv("MAIL_SENDER")

	log.Println("Authentication V3  Initialized")
}
