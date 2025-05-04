package handlers

import (
	"time"
	"net/http"
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"crypto/sha256"
	"log/slog"
	"database/sql"
	"fmt"
	"encoding/base64"

	"github.com/golang-jwt/jwt/v5"
    	"github.com/google/uuid"
	
	"auth_medods/internal/models"
	"auth_medods/internal/config"
)


var log *slog.Logger
var db *sql.DB
var cfg *config.Config

func SetupHandlers(logger *slog.Logger, DB *sql.DB, config *config.Config){
	log = logger
	db = DB
	cfg = config
}


func ReadUserIP(r *http.Request) string {
    	IPAddress := r.Header.Get("X-Real-Ip")
    	if IPAddress == "" {
        	IPAddress = r.Header.Get("X-Forwarded-For")
    	}
    	if IPAddress == "" {
        	IPAddress = r.RemoteAddr
    	}
    	return IPAddress
}

func GetUser(user *models.User, r *http.Request) (error){
	err := json.NewDecoder(r.Body).Decode(user)//potential err
        if err != nil {
                log.Info("error in decoding:")
        	return err
	}
	return nil
}

func Register(user models.User) error {

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
        if err != nil{
                log.Error("error in hashedPassword:")
                return err
        }

        _, err = db.Exec("INSERT INTO medods(id, password, ip) VALUES($1, $2, $3)", user.ID, string(hashedPassword), user.IP)
        if err != nil{
                log.Error("insert error:")
                return err
        }
        return nil

}

func RegisterHandler(w http.ResponseWriter, r *http.Request){
	var user models.User
	err := GetUser(&user, r)
	if err != nil{
		log.Error("err in GetUser", err)
	}
	user.IP = ReadUserIP(r)
	
	err = Register(user)
	if err != nil{
		log.Error("err in Register", err)
	} else {
		log.Info("User registered successfully")
	}
}

func Login(user *models.User) error {
 	var hashedPassword string

	err := db.QueryRow("SELECT password, ip FROM medods WHERE id = $1", user.ID).Scan(&hashedPassword, &user.IP)
        if err != nil{
                log.Error("err:")
		return err
        }

        err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(user.Password))
        if err != nil{
                log.Error("err:", err)
                return err
        }
	return nil
}
func LoginHandler(w http.ResponseWriter, r *http.Request){
	var user models.User
	err := GetUser(&user, r)
	if err != nil {
		log.Error("err in GetUser", err)
		return 
	}

	err = Login(&user)
	if err != nil{
		log.Error("err in Login", err)
		return
	} else {
		log.Info("authentication is successful")
	}

	tokens, err := CreateTokens(user)
	if err != nil{
		log.Error("err:", err)
	}
	w.Header().Set("Content-Type", "application/json")
        err = json.NewEncoder(w).Encode(tokens)
}

func RefreshHandlerDecodeAndCompare(user *models.User, tokenString string) error {

	decodedRefreshToken, _ := base64.StdEncoding.DecodeString(tokenString)
        refreshToken, err := jwt.Parse(string(decodedRefreshToken), func(token *jwt.Token) (interface{}, error) {
                if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                        return nil, http.ErrAbortHandler
                }
                return []byte(cfg.SecretString), nil
        })

        if err != nil{
                log.Error("token is bad")
		return err
        }

        claims, ok := refreshToken.Claims.(jwt.MapClaims)
        if ok && refreshToken.Valid{
        	
 		var hashedRefreshTokenFromDB, ipFromDB string
        	var is_used bool

        	err = db.QueryRow("SELECT refresh, password, is_used, ip FROM medods WHERE id = $1", claims["id"]).Scan(&hashedRefreshTokenFromDB, &user.Password, &is_used, &ipFromDB)
        	if err != nil {
                	log.Error("err in database")
			return err
        	}
        	if is_used{
                	log.Info("this refresh token has already used")
        		return http.ErrAbortHandler
		}

        	if ipFromDB != user.IP{
                	fmt.Println("###IP address of User changed###", "###The message has already sent to User@gmail.com###")
        	}

		tokenHash := sha256.Sum256([]byte(decodedRefreshToken))

        	err = bcrypt.CompareHashAndPassword([]byte(hashedRefreshTokenFromDB), tokenHash[:])
        	if err != nil{
                	log.Error("err in comparing of tokens")
                	return err
        	}

        	_, err = db.Exec("UPDATE medods SET is_used = true WHERE id = $1", claims["id"])
        	if err != nil {
                	log.Error("err in database")
			return err
        	}

        	var userID int//lastinsert id do it
        	err = db.QueryRow("SELECT id FROM medods ORDER BY id desc limit 1").Scan(&userID)
        	if err != nil {
                	log.Error("err in database")
			return err
        	}
        	user.ID = userID + 1

        	_, err = db.Exec("INSERT INTO medods(id, password, ip) VALUES($1, $2, $3)", user.ID, user.Password, user.IP)
        	if err != nil{
                	log.Error("err in database")
			return err
        	}

	} else {
		log.Error("token is not valid")
		return http.ErrAbortHandler
	}
	log.Debug("RefreshHandlerDecodeAndCompare finished successfully")
	return nil
}

func RefreshHandler(w http.ResponseWriter, r *http.Request){

	tokenString := r.Header.Get("Authorization")[7:]
  	if tokenString == "" {
    		w.WriteHeader(http.StatusUnauthorized)
    		fmt.Fprint(w, "Missing authorization header")
  	}

	var user models.User
	user.IP = ReadUserIP(r)
			
	err := RefreshHandlerDecodeAndCompare(&user, tokenString)
	if err != nil{
		log.Error("err in RefreshHandlerDecodeAndCompare:", err)
		return
	}

	tokens, err := CreateTokens(user)
	if err != nil {
                log.Error("err:", err)
        }
	w.Header().Set("Content-Type", "application/json")
      	err = json.NewEncoder(w).Encode(tokens)
}

func CreateTokens(user models.User) (map[string]string, error){
	id := uuid.New().String()
        accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
                "id":user.ID,
                "pair_id":id,
                "exp":time.Now().Add(time.Hour * 2).Unix(),
		"ip":user.IP,
        })

        accessTokenString, err := accessToken.SignedString([]byte(cfg.SecretString))
        if err != nil {
                log.Error("err in signing of token")
		return nil, err
        }

        refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
                "id":user.ID,
                "pair_id":id,
                "exp":time.Now().Add(time.Hour * 24 * 7).Unix(),
		"ip":user.IP,
        })

        refreshTokenString, err := refreshToken.SignedString([]byte(cfg.SecretString))
        if err != nil{
                log.Error("err in signing of token")
                return nil, err
        }

        tokenHash := sha256.Sum256([]byte(refreshTokenString))
        hashedRefreshTokenString, err := bcrypt.GenerateFromPassword(tokenHash[:], bcrypt.DefaultCost)
        if err != nil {
                log.Error("err in hashing")
		return nil, err
        }

        _, err = db.Exec("UPDATE medods SET refresh = $1, pair_id = $2 WHERE id = $3", string(hashedRefreshTokenString), id, user.ID)
        if err != nil {
                log.Error("err in updating")
		return nil, err
        }

	tokens := map[string]string{"accessTokenString":accessTokenString, "refreshTokenString":base64.StdEncoding.EncodeToString([]byte(refreshTokenString))}
	
	log.Debug("tokens are made")
	return tokens, nil
}
