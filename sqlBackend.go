package httpauth

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
)

// SqlAuthBackend database and database connection information.
type SqlAuthBackend struct {
	driverName     string
	dataSourceName string
	db             *sql.DB

	// prepared statements
	userByEmailStmt *sql.Stmt
	userByIDStmt    *sql.Stmt
	usersStmt       *sql.Stmt
	insertStmt      *sql.Stmt
	updateStmt      *sql.Stmt
	deleteStmt      *sql.Stmt
}

func mksqlerror(msg string) error {
	return errors.New("sqlbackend: " + msg)
}

// NewSqlAuthBackend initializes a new backend by testing the database
// connection and making sure the storage table exists. The table is called
// USER.
//
// Returns an error if connecting to the database fails, pinging the database
// fails, or creating the table fails.
//
// This uses the databases/sql package to open a connection. Its parameters
// should match the sql.Open function. See
// http://golang.org/pkg/database/sql/#Open for more information.
//
// Be sure to import "database/sql" and your driver of choice. If you're not
// using sql for your own purposes, you'll need to use the underscore to import
// for side effects; see http://golang.org/doc/effective_go.html#blank_import.
func NewSqlAuthBackend(driverName, dataSourceName string) (b SqlAuthBackend, e error) {
	b.driverName = driverName
	b.dataSourceName = dataSourceName
	if driverName == "sqlite3" {
		if _, err := os.Stat(dataSourceName); os.IsNotExist(err) {
			return b, ErrMissingBackend
		}
	}
	db, err := sql.Open(driverName, dataSourceName)
	if err != nil {
		return b, mksqlerror(err.Error())
	}
	err = db.Ping()
	if err != nil {
		return b, mksqlerror(err.Error())
	}
	b.db = db
	_, err = db.Exec(`create table if not exists "USER" (id SERIAL PRIMARY KEY NOT NULL, email varchar(255), hash varchar(255), role varchar(255), confirm_key varchar(255))`)
	if err != nil {
		return b, mksqlerror(err.Error())
	}

	// prepare statements for concurrent use and better preformance
	//
	// NOTE:
	// I don't want to have to check if it's postgres, but postgres uses
	// different tokens for placeholders. :( Also be aware that postgres
	// lowercases all these column names.
	//
	// Thanks to mjhall for letting me know about this.
	if driverName == "postgres" {
		b.userByEmailStmt, err = db.Prepare(`select id, hash, role from "USER" where email = $1`)
		if err != nil {
			return b, mksqlerror(fmt.Sprintf("userbyemailstmt: %v", err))
		}
		b.userByIDStmt, err = db.Prepare(`select email, hash, role from "USER" where id = $1`)
		if err != nil {
			return b, mksqlerror(fmt.Sprintf("userbyidstmt: %v", err))
		}
		b.usersStmt, err = db.Prepare(`select id, email, hash, role from "USER"`)
		if err != nil {
			return b, mksqlerror(fmt.Sprintf("usersstmt: %v", err))
		}
		b.insertStmt, err = db.Prepare(`insert into "USER" (email, hash, role, confirm_key) values ($1, $2, $3, $4)`)
		if err != nil {
			return b, mksqlerror(fmt.Sprintf("insertstmt: %v", err))
		}
		b.updateStmt, err = db.Prepare(`update "USER" set email = $1, hash = $2, role = $3 where id = $4`)
		if err != nil {
			return b, mksqlerror(fmt.Sprintf("updatestmt: %v", err))
		}
		b.deleteStmt, err = db.Prepare(`delete from "USER" where id = $1`)
		if err != nil {
			return b, mksqlerror(fmt.Sprintf("deletestmt: %v", err))
		}
	} else {
		b.userByEmailStmt, err = db.Prepare(`select email, hash, role from "USER" where email = ?`)
		if err != nil {
			return b, mksqlerror(fmt.Sprintf("userstmt: %v", err))
		}
		b.userByIDStmt, err = db.Prepare(`select id, hash, role from "USER" where id = ?`)
		if err != nil {
			return b, mksqlerror(fmt.Sprintf("userbyidstmt: %v", err))
		}
		b.usersStmt, err = db.Prepare(`select id, email, hash, role from "USER"`)
		if err != nil {
			return b, mksqlerror(fmt.Sprintf("usersstmt: %v", err))
		}
		b.insertStmt, err = db.Prepare(`insert into "USER" (id, email, hash, role, confirm_key) values (?, ?, ?, ?, ?)`)
		if err != nil {
			return b, mksqlerror(fmt.Sprintf("insertstmt: %v", err))
		}
		b.updateStmt, err = db.Prepare(`update "USER" set email = ?, hash = ?, role = ? where id = ?`)
		if err != nil {
			return b, mksqlerror(fmt.Sprintf("updatestmt: %v", err))
		}
		b.deleteStmt, err = db.Prepare(`delete from "USER" where id = ?`)
		if err != nil {
			return b, mksqlerror(fmt.Sprintf("deletestmt: %v", err))
		}
	}

	return b, nil
}

// User returns the user with the given email. Error is set to
// ErrMissingUser if user is not found.
func (b SqlAuthBackend) UserByEmail(email string) (user UserData, e error) {
	row := b.userByEmailStmt.QueryRow(email)
	err := row.Scan(&user.ID, &user.Hash, &user.Role)
	if err != nil {
		if err == sql.ErrNoRows {
			return user, ErrMissingUser
		}
		return user, mksqlerror(err.Error())
	}
	user.Email = email
	return user, nil
}

// User returns the user with the given id. Error is set to
// ErrMissingUser if user is not found.
func (b SqlAuthBackend) UserByID(id int) (user UserData, e error) {
	row := b.userByIDStmt.QueryRow(id)
	err := row.Scan(&user.Email, &user.Hash, &user.Role)
	if err != nil {
		if err == sql.ErrNoRows {
			return user, ErrMissingUser
		}
		return user, mksqlerror(err.Error())
	}
	user.ID = id
	return user, nil
}

// Users returns a slice of all users.
func (b SqlAuthBackend) Users() (us []UserData, e error) {
	rows, err := b.usersStmt.Query()
	if err != nil {
		return us, mksqlerror(err.Error())
	}
	var (
		id          int
		email, role string
		hash        []byte
	)
	for rows.Next() {
		err = rows.Scan(&id, &email, &hash, &role)
		if err != nil {
			return us, mksqlerror(err.Error())
		}
		us = append(us, UserData{ID: id, Email: email, Hash: hash, Role: role})
	}
	return us, nil
}

// SaveUser adds a new user, replacing one with the same username.
func (b SqlAuthBackend) SaveUser(user UserData) (err error) {
	if _, err := b.UserByID(user.ID); err == nil {
		_, err = b.updateStmt.Exec(user.Email, user.Hash, user.Role, user.ID)
	} else {
		_, err = b.insertStmt.Exec(user.Email, user.Hash, user.Role, user.ConfirmKey)
	}
	return
}

// DeleteUser removes a user, raising ErrDeleteNull if that user was missing.
func (b SqlAuthBackend) DeleteUser(email string) error {
	result, err := b.deleteStmt.Exec(email)
	if err != nil {
		return mksqlerror(err.Error())
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return mksqlerror(err.Error())
	}
	if rows == 0 {
		return ErrDeleteNull
	}
	return nil
}

// Close cleans up the backend by terminating the database connection.
func (b SqlAuthBackend) Close() {
	b.db.Close()
	b.userByEmailStmt.Close()
	b.userByIDStmt.Close()
	b.usersStmt.Close()
	b.insertStmt.Close()
	b.updateStmt.Close()
	b.deleteStmt.Close()
}
