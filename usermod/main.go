package main

import (
    "bufio"
    "flag"
    "github.com/TNO/auth-by-email/auth-by-email"
    "log"
    "os"
    "strings"
)

func main() {
    database := flag.String("database", "/tmp/database", "Directory in which the database lives")
    mode := flag.String("mode", "add", "What to do with input e-mail addresses {add|delete|invalidate|debug} (the latter invalidates cookies and e-mails but doesn't delete the user)")
    flag.Parse()

    if !(*mode == "add" || *mode == "delete" || *mode == "invalidate" || *mode == "debug") {
        log.Fatalf("Please specify --mode {add|delete|invalidate}, you specified `%v`", *mode)
    }

    authbyemail.InitializeCrypto()
    db := authbyemail.NewDiskBackedDatabase(
        &authbyemail.Config{Database: *database},
        log.New(os.Stderr, "(AuthByEmail) ", log.LstdFlags))

    if *mode == "debug" {
        db.DelUser(authbyemail.UserID("nobody@nowhere")) // Prints debug info
        return
    }

    successes := 0
    stdin := bufio.NewReader(os.Stdin)
    for {
        line, err := stdin.ReadString('\n')
        if err != nil {
            break
        }

        email, err := authbyemail.NewEmailAddrFromString(strings.TrimSpace(line))
        if err != nil {
            log.Printf("Can not parse e-mail address `%v`", line)
            continue
        }
        userid := authbyemail.CRYPTO.UserIDfromEmail(email)

        // "invalidate" means to delete the user (which removes all tokens), and then to add them back
        if *mode == "delete" || *mode == "invalidate" {
            err := db.DelUser(userid)
            if err != nil {
                log.Printf("Could not delete user %v (%v): %v", email.String(), userid, err)
                continue
            }
        }
        if *mode == "add" || *mode == "invalidate" {
            db.AddUser(userid)
        }

        successes += 1
    }

    log.Printf("Finished. %v entries processed successfully.", successes)
}
