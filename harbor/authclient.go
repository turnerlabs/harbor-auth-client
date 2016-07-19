package harbor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/asaskevich/govalidator"
	"github.com/turnerlabs/harbor-auth-client"
)

type harborAuthClient struct {
	url string
}

type loginInfo struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type logoutInfo struct {
	Username string `json:"username"`
	Token    string `json:"token"`
}

type harborLogin struct {
	Token   string `json:"token"`
	Success bool   `json:"success"`
}

type harborLogout struct {
	Success bool `json:"success"`
}

// NewAuthClient -
func NewAuthClient(url string) auth.Auth {
	if len(url) == 0 {
		return nil
	}

	client := newHarborAuthClient(url)
	return &client
}

func newHarborAuthClient(url string) harborAuthClient {
	s := harborAuthClient{url: url}
	return s
}

// Login -
func (s *harborAuthClient) Login(username string, password string) (string, bool, error) {
	var hLogin harborLogin
	if !govalidator.IsByteLength(password, 8, 20) {
		return "", false, errors.New("Password is either less than the minimum or over the maximum number of characters")
	}

	if !govalidator.IsAlpha(username) {
		return "", false, errors.New("Usernames must be alphabetical")
	}

	fullURL := s.url + "/v1/auth/gettoken"
	client := &http.Client{}

	buf := loginInfo{}
	buf.Username = username
	buf.Password = password

	byteBuf, err := json.Marshal(buf)

	req, err := http.NewRequest("POST", fullURL, bytes.NewBuffer(byteBuf))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err.Error())
		return "", false, err
	}

	defer resp.Body.Close()

	status := resp.StatusCode
	if status != 200 {
		return "", false, errors.New("Invalid Status Code: " + resp.Status)
	}

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", false, errors.New("Error in ReadAll")
	}

	json.Unmarshal(responseBody, &hLogin)

	return hLogin.Token, hLogin.Success, nil
}

// Logout -
func (s *harborAuthClient) Logout(username string, token string) (bool, error) {
	var hLogout harborLogout
	if !govalidator.IsAlpha(username) {
		return false, errors.New("Usernames must be alphabetical")
	}

	if len(token) == 0 {
		return false, errors.New("Empty token")
	}

	fullURL := s.url + "/v1/auth/destroytoken"
	client := &http.Client{}

	buf := logoutInfo{}
	buf.Username = username
	buf.Token = token

	byteBuf, err := json.Marshal(buf)

	req, err := http.NewRequest("POST", fullURL, bytes.NewBuffer(byteBuf))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err.Error())
		return false, err
	}

	defer resp.Body.Close()

	status := resp.StatusCode
	if status != 200 {
		return false, errors.New("Invalid Status Code: " + resp.Status)
	}

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, errors.New("Error in ReadAll")
	}

	json.Unmarshal(responseBody, &hLogout)

	return hLogout.Success, nil
}

func (s *harborAuthClient) IsAuthenticated(username string, token string) (bool, error) {
	var hLogout harborLogout
	if !govalidator.IsAlpha(username) {
		return false, errors.New("Usernames must be alphabetical")
	}

	if len(token) == 0 {
		return false, errors.New("Empty token")
	}

	fullURL := s.url + "/v1/auth/checktoken"
	client := &http.Client{}

	// not really logging out here but its the same structure
	buf := logoutInfo{}
	buf.Username = username
	buf.Token = token

	byteBuf, err := json.Marshal(buf)

	req, err := http.NewRequest("POST", fullURL, bytes.NewBuffer(byteBuf))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err.Error())
		return false, err
	}

	defer resp.Body.Close()

	status := resp.StatusCode
	if status != 200 {
		return false, errors.New("Invalid Status Code: " + resp.Status)
	}

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, errors.New("Error in ReadAll")
	}

	json.Unmarshal(responseBody, &hLogout)

	return hLogout.Success, nil

}

func (s *harborAuthClient) GetUser() error {
	return errors.New("GetUser error")
}

func (s *harborAuthClient) GetToken() error {
	return errors.New("GetToken error")
}
