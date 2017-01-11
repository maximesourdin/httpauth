// Package httpauth implements cookie/session based authentication and
// authorization. Intended for use with the net/http or github.com/gorilla/mux
// packages, but may work with github.com/codegangsta/martini as well.
// Credentials are stored as a username + password hash, computed with bcrypt.
//
// Three user storage systems are currently implemented: file based
// (encoding/gob), sql databases (database/sql), and MongoDB databases.
//
// Access can be restricted by a users' role. A higher role will give more
// access.
//
// Users can be redirected to the page that triggered an authentication error.
//
// Messages describing the reason a user could not authenticate are saved in a
// cookie, and can be accessed with the Messages function.
//
// Example source can be found at
// https://github.com/apexskier/httpauth/blob/master/examples/server.go
package httpauth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"fmt"
	"strings"
	"strconv"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

// ErrDeleteNull is returned by DeleteUser when that user didn't exist at the
// time of call.
// ErrMissingUser is returned by Users when a user is not found.
var (
	ErrDeleteNull  = mkerror("deleting nonexistent user")
	ErrMissingUser = mkerror("can't find user")
)

// Role represents an interal role. Roles are essentially a string mapped to an
// integer. Roles must be greater than zero.
type Role int

// UserData represents a single user. It contains the users username, email,
// and role as well as a hash of their password. When creating
// users, you should not specify a hash; it will be generated in the Register
// and Update functions.
type UserData struct {
	ID         int    `bson:"id"`
	Email      string `bson:"email"`
	Hash       []byte `bson:"hash"`
	Role       string `bson:"role"`
	ConfirmKey string `bson:"confirm_key"`
	Active     int    `bson:"active"`
}

// Authorizer structures contain the store of user session cookies a reference
// to a backend storage system.
type Authorizer struct {
	cookiejar   *sessions.CookieStore
	backend     AuthBackend
	defaultRole string
	roles       map[string]Role
}

// The AuthBackend interface defines a set of methods an AuthBackend must
// implement.
type AuthBackend interface {
	SaveUser(u UserData) (e error)
	UserByEmail(email string) (user UserData, e error)
	UserByID(id int) (user UserData, e error)
	Users() (users []UserData, e error)
	DeleteUser(email string) error
	Close()
}

type AccessToken struct {
   Token  string
   Expiry int64
}

// Helper function to add a user directed message to a message queue.
func (a Authorizer) addMessage(rw http.ResponseWriter, req *http.Request, message string) {
	messageSession, _ := a.cookiejar.Get(req, "messages")
	defer messageSession.Save(req, rw)
	messageSession.AddFlash(message)
}

// Helper function to save a redirect to the page a user tried to visit before
// logging in.
func (a Authorizer) goBack(rw http.ResponseWriter, req *http.Request) {
	redirectSession, _ := a.cookiejar.Get(req, "redirects")
	defer redirectSession.Save(req, rw)
	redirectSession.Flashes()
	redirectSession.AddFlash(req.URL.Path)
}

func mkerror(msg string) error {
	return errors.New("httpauth: " + msg)
}

// NewAuthorizer returns a new Authorizer given an AuthBackend, a cookie store
// key, a default user role, and a map of roles. If the key changes, logged in
// users will need to reauthenticate.
//
// Roles are a map of string to httpauth.Role values (integers). Higher Role values
// have more access.
//
// Example roles:
//
//     var roles map[string]httpauth.Role
//     roles["user"] = 2
//     roles["admin"] = 4
//     roles["moderator"] = 3
func NewAuthorizer(backend AuthBackend, key []byte, defaultRole string, roles map[string]Role) (Authorizer, error) {
	var a Authorizer
	a.cookiejar = sessions.NewCookieStore([]byte(key))
	a.backend = backend
	a.roles = roles
	a.defaultRole = defaultRole
	if _, ok := roles[defaultRole]; !ok {
		return a, mkerror("httpauth: defaultRole missing")
	}
	return a, nil
}

// Login logs a user in. They will be redirected to dest or to the last
// location an authorization redirect was triggered (if found) on success. A
// message will be added to the session on failure with the reason.
func (a Authorizer) Login(rw http.ResponseWriter, req *http.Request, e string, p string, dest string) error {
	session, _ := a.cookiejar.Get(req, "auth")

	user, err := a.backend.UserByEmail(e)
	if session.Values["userID"] == user.ID {
		return mkerror("already authenticated")
	}
	if err == nil {
		verify := bcrypt.CompareHashAndPassword(user.Hash, []byte(p))
		if verify != nil {
			a.addMessage(rw, req, "Invalid username or password.")
			return mkerror("password doesn't match")
		}
	} else {
		a.addMessage(rw, req, "Invalid username or password.")
		return mkerror("user not found")
	}
	if user.Active == 0 {
		a.addMessage(rw, req, "Account not active.")
		return mkerror("Account not active")
	}
	session.Values["userID"] = user.ID
	session.Save(req, rw)

	redirectSession, _ := a.cookiejar.Get(req, "redirects")
	if flashes := redirectSession.Flashes(); len(flashes) > 0 {
		dest = flashes[0].(string)
	}
	http.Redirect(rw, req, dest, http.StatusSeeOther)
	return nil
}

func (a Authorizer) LoginWithFacebook(rw http.ResponseWriter, req *http.Request, e string, dest string) error {
	session, _ := a.cookiejar.Get(req, "auth")

	code := req.FormValue("code")
	ClientId := "693400277501957"
	ClientSecret := "LesCouillesDeMaximeSententLePate"

	user, err := a.backend.UserByEmail(e)
	if session.Values["userID"] == user.ID {
		return mkerror("already authenticated")
	}
	if err != nil {
		a.addMessage(rw, req, "Invalid username or password.")
		return mkerror("user not found")
	}
	if user.Active == 0 {
		a.addMessage(rw, req, "Account not active.")
		return mkerror("Account not active")
	}
	accessToken := getAccessToken(ClientId, code, ClientSecret, "")
	fmt.Println(accessToken)
	if response, err := http.Get("https://graph.facebook.com/me?access_token=" + accessToken.Token); err != nil {
		fmt.Println(response)
		a.addMessage(rw, req, "Error")
		return mkerror("Cannot connect to Facebook")
	} else {
		fmt.Println(response)
	}

	session.Values["userID"] = user.ID
	session.Save(req, rw)

	redirectSession, _ := a.cookiejar.Get(req, "redirects")
	if flashes := redirectSession.Flashes(); len(flashes) > 0 {
		dest = flashes[0].(string)
	}
	http.Redirect(rw, req, dest, http.StatusSeeOther)

	return nil
}

// Register and save a new user. Returns an error and adds a message if the
// username is in use.
//
// Pass in a instance of UserData with at least a username and email specified. If no role
// is given, the default one is used.
func (a Authorizer) Register(rw http.ResponseWriter, req *http.Request, user UserData, password string) (UserData, error) {

	if user.Email == "" {
		return user, mkerror("no email given")
	}
	if user.Hash != nil {
		return user, mkerror("hash will be overwritten")
	}
	if password == "" {
		return user, mkerror("no password given")
	}

	// Validate email
	_, err := a.backend.UserByEmail(user.Email)
	if err == nil {
		a.addMessage(rw, req, "Email has been taken.")
		return user, mkerror("user already exists")
	} else if err != ErrMissingUser {
		if err != nil {
			return user, mkerror(err.Error())
		}
		return user, nil
	}

	// Generate and save hash
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return user, mkerror("couldn't save password: " + err.Error())
	}
	user.Hash = hash

	// Generate and save confirm key
	// Example: this will give us a 44 byte, base64 encoded output
	token, err := GenerateRandomString(32)
	if err != nil {
		return user, mkerror("couldn't save the confirm key: " + err.Error())
	}
	user.ConfirmKey = token

	// Validate role
	if user.Role == "" {
		user.Role = a.defaultRole
	} else {
		if _, ok := a.roles[user.Role]; !ok {
			return user, mkerror("nonexistent role")
		}
	}

	err = a.backend.SaveUser(user)
	if err != nil {
		a.addMessage(rw, req, err.Error())
		return user, mkerror(err.Error())
	}
	user, err = a.backend.UserByEmail(user.Email)
	return user, nil
}

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

// GenerateRandomString returns a URL-safe, base64 encoded
// securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomString(s int) (string, error) {
	b, err := GenerateRandomBytes(s)
	return base64.URLEncoding.EncodeToString(b), err
}

// Update changes data for an existing user.
// The behavior of the update varies depending on how the arguments are passed:
//  If an empty username u is passed then it updates the current user from the session
//    (self-edit scenario)
//  If the username u is passed explicitly then it updates the passed username
//    (admin update scenario)
//  If an empty password p is passed then it keeps the original rather than
//    regenerating the hash, if a new password is passed then it regenerates the hash.
//  If an empty email e is passed then it keeps the orginal rather than updating it,
//    if a new email is passedn then it updates it.
func (a Authorizer) Update(rw http.ResponseWriter, req *http.Request, i int, e string, po string, pn string, ac int) error {
	var (
		id     int
		email  string
		hash   []byte
		active int
		ok     bool
	)
	if i != 0 {
		id = i
	} else {
		authSession, err := a.cookiejar.Get(req, "auth")
		if err != nil {
			return mkerror("couldn't get session needed to update user: " + err.Error())
		}
		id, ok = authSession.Values["userID"].(int)
		if !ok {
			return mkerror("not logged in")
		}
	}
	user, err := a.backend.UserByID(id)
	if err == ErrMissingUser {
		a.addMessage(rw, req, "User doesn't exist.")
		return mkerror("user doesn't exists")
	} else if err != nil {
		return mkerror(err.Error())
	}
	if po != "" && pn != "" {
		verify := bcrypt.CompareHashAndPassword(user.Hash, []byte(po))
		if verify != nil {
			a.addMessage(rw, req, "Password doesn't match")
			return mkerror("password doesn't match")
		}
		hash, err = bcrypt.GenerateFromPassword([]byte(pn), bcrypt.DefaultCost)
		if err != nil {
			return mkerror("couldn't save password: " + err.Error())
		}
	} else {
		hash = user.Hash
	}
	if e != "" {
		email = e
	} else {
		email = user.Email
	}
	if ac == 1 {
		active = ac
	}

	newuser := UserData{ID: id, Email: email, Hash: hash, Role: user.Role, Active: active}

	err = a.backend.SaveUser(newuser)
	if err != nil {
		a.addMessage(rw, req, err.Error())
	}
	return nil
}

// Activate checks if the confirm key is correct to the user, and then
// activate his account.
func (a Authorizer) Activate(rw http.ResponseWriter, req *http.Request, i int, key string) error {
	user, err := a.backend.UserByID(i)
	if err != nil {
		a.addMessage(rw, req, "Invalid username or password.")
		return mkerror("user not found")
	}
	if user.Active == 1 {
		a.addMessage(rw, req, "User already active.")
		return mkerror("user already active")
	}
	if user.ConfirmKey == key {
		err = a.Update(rw, req, user.ID, "", "", "", 1)
		if err != nil {
			return mkerror("couldn't update user")
		}
	} else {
		a.addMessage(rw, req, "Invalid confirmation key")
		return mkerror("invalid confirmation key")
	}
	return nil
}

// Authorize checks if a user is logged in and returns an error on failed
// authentication. If redirectWithMessage is set, the page being authorized
// will be saved and a "Login to do that." message will be saved to the
// messages list. The next time the user logs in, they will be redirected back
// to the saved page.
func (a Authorizer) Authorize(rw http.ResponseWriter, req *http.Request, redirectWithMessage bool) error {
	authSession, err := a.cookiejar.Get(req, "auth")
	if err != nil {
		if redirectWithMessage {
			a.goBack(rw, req)
		}
		return mkerror("new authorization session")
	}
	/*if authSession.IsNew {
	    if redirectWithMessage {
	        a.goBack(rw, req)
	        a.addMessage(rw, req, "Log in to do that.")
	    }
	    return mkerror("no session existed")
	}*/
	id := authSession.Values["userID"]
	if !authSession.IsNew && id != nil {
		_, err := a.backend.UserByID(id.(int))
		if err == ErrMissingUser {
			authSession.Options.MaxAge = -1 // kill the cookie
			authSession.Save(req, rw)
			if redirectWithMessage {
				a.goBack(rw, req)
				a.addMessage(rw, req, "Log in to do that.")
			}
			return mkerror("user not found")
		} else if err != nil {
			return mkerror(err.Error())
		}
	}
	if id == nil {
		if redirectWithMessage {
			a.goBack(rw, req)
			a.addMessage(rw, req, "Log in to do that.")
		}
		return mkerror("user not logged in")
	}
	return nil
}

// AuthorizeRole runs Authorize on a user, then makes sure their role is at
// least as high as the specified one, failing if not.
func (a Authorizer) AuthorizeRole(rw http.ResponseWriter, req *http.Request, role string, redirectWithMessage bool) error {
	r, ok := a.roles[role]
	if !ok {
		return mkerror("role not found")
	}
	if err := a.Authorize(rw, req, redirectWithMessage); err != nil {
		return mkerror(err.Error())
	}
	authSession, _ := a.cookiejar.Get(req, "auth") // should I check err? I've already checked in call to Authorize
	id := authSession.Values["userID"]
	if user, err := a.backend.UserByID(id.(int)); err == nil {
		if a.roles[user.Role] >= r {
			return nil
		}
		a.addMessage(rw, req, "You don't have sufficient privileges.")
		return mkerror("user doesn't have high enough role")
	}
	return mkerror("user not found")
}

// CurrentUser returns the currently logged in user and a boolean validating
// the information.
func (a Authorizer) CurrentUser(rw http.ResponseWriter, req *http.Request) (user UserData, e error) {
	if err := a.Authorize(rw, req, false); err != nil {
		return user, mkerror(err.Error())
	}
	authSession, _ := a.cookiejar.Get(req, "auth")

	id, ok := authSession.Values["userID"].(int)
	if !ok {
		return user, mkerror("User not found in authsession")
	}
	return a.backend.UserByID(id)
}

// Logout clears an authentication session and add a logged out message.
func (a Authorizer) Logout(rw http.ResponseWriter, req *http.Request) error {
	session, _ := a.cookiejar.Get(req, "auth")
	defer session.Save(req, rw)

	session.Options.MaxAge = -1 // kill the cookie
	a.addMessage(rw, req, "Logged out.")
	return nil
}

// DeleteUser removes a user from the Authorize. ErrMissingUser is returned if
// the user to be deleted isn't found.
func (a Authorizer) DeleteUser(email string) error {
	err := a.backend.DeleteUser(email)
	if err != nil && err != ErrDeleteNull {
		return mkerror(err.Error())
	}
	return err
}

// Messages fetches a list of saved messages. Use this to get a nice message to print to
// the user on a login page or registration page in case something happened
// (username taken, invalid credentials, successful logout, etc).
func (a Authorizer) Messages(rw http.ResponseWriter, req *http.Request) []string {
	session, _ := a.cookiejar.Get(req, "messages")
	flashes := session.Flashes()
	session.Save(req, rw)
	var messages []string
	for _, val := range flashes {
		messages = append(messages, val.(string))
	}
	return messages
}

func getAccessToken(client_id string, code string, secret string, callbackUri string) AccessToken {
 	fmt.Println("GetAccessToken")
 	//https://graph.facebook.com/oauth/access_token?client_id=YOUR_APP_ID&redirect_uri=YOUR_REDIRECT_URI&client_secret=YOUR_APP_SECRET&code=CODE_GENERATED_BY_FACEBOOK
 	response, err := http.Get("https://graph.facebook.com/oauth/access_token?client_id=" +
 		client_id + "&redirect_uri=" + callbackUri +
 		"&client_secret=" + secret + "&code=" + code)

 	if err == nil {
		fmt.Println(response)

 		auth := readHttpBody(response)

		fmt.Println(auth)

 		var token AccessToken

 		tokenArr := strings.Split(auth, "&")

 		token.Token = strings.Split(tokenArr[0], "=")[1]
 		expireInt, err := strconv.Atoi(strings.Split(tokenArr[1], "=")[1])

 		if err == nil {
 			token.Expiry = int64(expireInt)
 		}

 		return token
 	}

 	var token AccessToken

 	return token
 }

 func readHttpBody(response *http.Response) string {

 	fmt.Println("Reading body")

 	bodyBuffer := make([]byte, 5000)
 	var str string

	fmt.Println(response)
	fmt.Println("Reading")

 	count, err := response.Body.Read(bodyBuffer)
	fmt.Println("after Reading")

 	for ; count > 0; count, err = response.Body.Read(bodyBuffer) {

 		if err != nil {
			fmt.Println(err)
			return err
 		}

 		str += string(bodyBuffer[:count])
 	}

 	return str

 }
