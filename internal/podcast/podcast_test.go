package podcast

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/sschwartz96/syncapod-backend/internal"
	"github.com/sschwartz96/syncapod-backend/internal/db"
)

var (
	testPod = &db.Podcast{
		ID:     uuid.MustParse("d6d07b86-29b3-4ae7-b321-89eb5b64484c"),
		Author: "sam schwartz",
	}
)

var (
	dbpg *pgxpool.Pool
)

func TestMain(m *testing.M) {
	// spin up docker container and return pgx pool
	var dockerCleanFunc func() error
	var err error
	dbpg, dockerCleanFunc, err = internal.StartDockerDB("db_auth")
	if err != nil {
		log.Fatalf("auth.TestMain() error setting up docker db: %v", err)
	}

	// setup db
	setupPodcastDB()

	// run tests
	runCode := m.Run()

	// close pgx pool
	dbpg.Close()

	// cleanup docker container
	err = dockerCleanFunc()
	if err != nil {
		log.Fatalf("podcast.TestMain() error cleaning up docker container: %v", err)
	}

	os.Exit(runCode)
}

func setupPodcastDB() {
}

func dbDeleteOrFail(table string) {
	_, err := dbpg.Exec(context.Background(),
		fmt.Sprintf("DELETE FROM %v", table))
	if err != nil {
		log.Fatalf("dbDeleteOrFail() could not delete rows of table: %v", err)
	}
}
