package handler

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"text/template"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/sschwartz96/syncapod-backend/internal/auth"
	"github.com/sschwartz96/syncapod-backend/internal/db"
	"github.com/stretchr/testify/require"
)

var testHandler *Handler

func TestMain(t *testing.M) {
	log.Println("running testMain")
	// connect to db
	pg, err := connectToDB()
	if err != nil {
		log.Fatalf("Handler.TestMain() error: %v", err)
	}

	// create controllers
	authC := auth.CreateAuthController(db.NewAuthStorePG(pg), db.NewOAuthStorePG(pg))

	// create handlers
	oauthHandler, err := createTestOAuthHandler(authC)
	if err != nil {
		log.Fatalf("Handler.TestMain() error creating oauthHandler: %v", err)
	}
	testHandler = &Handler{oauthHandler: oauthHandler}

	// setup
	setup(pg)

	os.Exit(t.Run())
}

func Test_Oauth(t *testing.T) {
	// oauth/login GET
	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://syncapod.com/oauth/login", nil)
	testHandler.oauthHandler.Login(res, req)
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("Test_Oauth() GET login error: %v", err)
	}
	require.Contains(t, string(body), "<h1>syncapod oauth2.0 login</h1>")

	// oauth/login POST
	res = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "https://syncapod.com/oauth/login", nil)
	req.Form = url.Values{"uname": {"oauthTest"}, "pass": {"password"}, "redirect_uri": {"https://testuri.com"}}
	testHandler.oauthHandler.Login(res, req)
	body, err = ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("Test_Oauth() POST login error: %v", err)
	}
	bodyString := string(body)
	require.Contains(t, string(body), "<a href=\"/oauth/authorize?")
	url := "https://syncapod.com" + bodyString[10:115]
	// seshKey := bodyString[68:104]
	//<a href="/oauth/authorize?client_id=&amp;redirect_uri=&amp;sesh_key=a1e34fc7-d657-40fb-abf4-b3b86a8f46be&amp;state=">See Other</a>.

	// oauth/authorize GET
	res = httptest.NewRecorder()
	req = httptest.NewRequest("GET", url, nil)
	testHandler.oauthHandler.Authorize(res, req)
	body, err = ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("Test_Oauth() GET authorize error: %v", err)
	}
	require.Contains(t, string(body), "<title>syncapod oauth authorization</title>")

	// oauth/authorize POST
	res = httptest.NewRecorder()
	req = httptest.NewRequest("POST", url, nil)
	testHandler.oauthHandler.Authorize(res, req)
	body, err = ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("Test_Oauth() POST authorize error: %v", err)
	}
	log.Println("ouath auth POST:", res.Code)
	//require.Contains(t, string(body), "<title>syncapod oauth authorization</title>")

	//testHandler.oauthHandler.Token()
}

func createTestOAuthHandler(authC auth.Auth) (*OauthHandler, error) {
	loginT, err := template.ParseFiles("../../templates/oauth/login.gohtml")
	if err != nil {
		return nil, err
	}
	authT, err := template.ParseFiles("../../templates/oauth/auth.gohtml")
	if err != nil {
		return nil, err
	}
	return &OauthHandler{authC, loginT, authT, "testClientID", "testClientSecret"}, nil
}

func setup(pg *pgxpool.Pool) {
	insertUser(pg, &db.UserRow{ID: uuid.MustParse("b7f85a20-9b8f-47f9-8cee-a553a24f2b6d"),
		Birthdate: time.Unix(0, 0), Email: "oauthTest@test.com", Username: "oauthTest",
		PasswordHash: []byte("$2a$10$bAkGU1SFc.oy9jz5/psXweSCqWG6reZr3Tl3oTKAgzBksPKHLG4bS")})
}

func connectToDB() (*pgxpool.Pool, error) {
	var pg *pgxpool.Pool
	// connect to db, stop after 5 seconds
	start := time.Now()
	fiveSec := time.Second * 5
	err := errors.New("start loop")
	for err != nil {
		if time.Since(start) > fiveSec {
			return nil, fmt.Errorf("connectToDB() error: took longer than 5 seconds to connect")
		}
		pg, err = pgxpool.Connect(context.Background(),
			fmt.Sprintf("postgres://postgres:secret@localhost:5432/postgres?sslmode=disable"),
		)
		time.Sleep(time.Millisecond * 250)
	}
	return pg, nil
}

func insertUser(pg *pgxpool.Pool, u *db.UserRow) {
	_, err := pg.Exec(context.Background(),
		"INSERT INTO users (id,email,username,birthdate,password_hash) VALUES($1,$2,$3,$4,$5)",
		u.ID, u.Email, u.Username, u.Birthdate, u.PasswordHash)
	if err != nil {
		log.Println("insertUser() id:", u.ID)
		log.Fatalln("insertUser() error:", err)
	}
}
