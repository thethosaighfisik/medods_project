package models 

type User struct{
        ID int `json:"id"`
        Password string `json:"password"`
	IP string
}
