package main

import (
    "bufio"
    "database/sql"
    "encoding/hex"
    "flag"
    sqlite "github.com/mattn/go-sqlite3"
    "log"
    "os"
    "strings"
    "time"
)

func main() {
    database := flag.String("database", "/tmp/database", "Directory in which the database lives")
    out := flag.String("out", "", "Where to save user hashes")
    in := flag.String("in", "", "Where to load user hashes")

    flag.Parse()

    if *out == "" && *in == "" {
        log.Fatalln("Please specify -out or -in")
    }

    db := NewDiskBackedDatabase(*database)

    if *out != "" {
        exportDB(db, *out)
    } else {
        importDB(db, *in)
    }
}

func exportDB(db *sql.DB, fname string) {
    file, err := os.Create(fname)
    if err != nil {
        log.Print("Error opening file,", err)
        return
    }

    result, err := db.Query(`select UserID from Users;`)
    if err != nil {
        log.Print("Can not get Users!", err)
        return
    }

    for result.Next() {
        var userID string
        if err = result.Scan(&userID); err != nil {
            log.Print("Error getting record,", err)
            continue
        }
        file.Write([]byte(hex.EncodeToString([]byte(userID)) + "\n"))
    }
    file.Close()
}

func importDB(db *sql.DB, fname string) {
    file, err := os.Open(fname)
    if err != nil {
        log.Print("Error opening file,", err)
        return
    }

    stdin := bufio.NewReader(file)
    for {
        line, err := stdin.ReadString('\n')
        if err != nil {
            break
        }
        userID, _ := hex.DecodeString(strings.TrimSpace(line))
        db.Exec(`insert into Users(userID) values(?);`, userID)
    }
    file.Close()
}

func NewDiskBackedDatabase(file string) *sql.DB {
    // The function used to check if a timestamp in the database is in not expired.
    timeNotInPast := func(timestamp string) bool {
        validUntil, err := time.Parse("2006-01-02 15:04:05.9999999-07:00", timestamp)
        if err != nil {
            log.Println("Could not parse database time", timestamp, "; this will likely lead to no cookies being valid;", err)
            return false // Fail safely by considering the timestamp expired
        }
        return validUntil.After(time.Now())
    }

    // Register our driver with the custom timestamp function.
    sql.Register("sqlite3_custom", &sqlite.SQLiteDriver{
        ConnectHook: func(conn *sqlite.SQLiteConn) error {
            if err := conn.RegisterFunc("timeNotInPast", timeNotInPast, false); err != nil {
                return err
            }
            return nil
        },
    })

    // Check if the database exists
    makeNew := false
    if file, err := os.Open(file); err != nil {
        makeNew = true
    } else {
        file.Close()
    }

    // Open the database, creating it if it doesn't exist
    db, err := sql.Open("sqlite3_custom", file)
    if err != nil {
        log.Panicf("Could not initialize database: %v", err)
    }

    // If it didn't exist, create the tables we need
    if makeNew {
        sqlStmt := `
            create table Users (userID text not null primary key);
            delete from Users;
            create table Cookies (cookieToken text not null primary key, userID text not null, validUntil datetime, isValidated bool, browser text);
            delete from Cookies;`
        _, err = db.Exec(sqlStmt)
        if err != nil {
            log.Panicf("Could not make new tables, %v", err)
        }
    }

    return db
}
