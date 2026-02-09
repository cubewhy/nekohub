use reqwest::StatusCode;
use serde_json::json;

use crate::helpers::TestApp;

#[tokio::test]
async fn register_user_success_with_valid_payload() {
    let app = TestApp::new().await;

    let username = "some_random_username";
    let password = "some_random_password";

    // /user/register
    let res = app
        .http_client
        .post(format!("{}/user/register", app.base_url))
        .json(&json!({
            "username": username,
            "password": password
        }))
        .send()
        .await
        .expect("Failed to send register user request");

    // make sure the response code is 201 Created
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "Register response status is not 201 CREATED, response={}",
        res.text().await.expect("Failed to recv res body")
    );

    let res_json: serde_json::Value = res
        .json()
        .await
        .expect("Failed to receive register response json");

    assert!(res_json.is_object(), "Response json is not an object");

    // make sure there is an username field in the response
    assert!(
        res_json.as_object().unwrap().contains_key("username"),
        "Response json doesn't contains the username field, response={:?}",
        res_json,
    );

    // for UI/UX, the token should be contained in the register response
    assert!(
        res_json.as_object().unwrap().contains_key("access_token"),
        "Response json doesn't contains the access_token field, response={:?}",
        res_json,
    );
    assert!(
        res_json.as_object().unwrap().contains_key("refresh_token"),
        "Response json doesn't contains the refresh_token field, response={:?}",
        res_json,
    );

    let user_option = sqlx::query!("SELECT (id) FROM users WHERE username = $1", username)
        .fetch_optional(&app.db)
        .await
        .expect("Failed to query db");

    assert!(
        user_option.is_some(),
        "Service didn't create user in database, which is not expected"
    );
}

#[tokio::test]
async fn register_user_failure_when_username_conflict() {
    let app = TestApp::new().await;

    let username = "some_random_username";
    let password = "some_random_password";

    // /user/register
    let res = app
        .http_client
        .post(format!("{}/user/register", app.base_url))
        .json(&json!({
            "username": username,
            "password": password
        }))
        .send()
        .await
        .expect("Failed to send register user request");

    // make sure the operation success
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "Register response status is not 201 CREATED, response={}",
        res.text().await.expect("Failed to recv res body")
    );

    // create another user
    let res = app
        .http_client
        .post(format!("{}/user/register", app.base_url))
        .json(&json!({
            "username": username,
            "password": password
        }))
        .send()
        .await
        .expect("Failed to send register user request");

    // make sure the operation success
    assert_eq!(
        res.status(),
        StatusCode::CONFLICT,
        "Register response status is not 409 CONFLICT, response={}",
        res.text().await.expect("Failed to recv res body")
    );
}

#[tokio::test]
async fn register_user_failure_when_username_conflict_ignore_case() {
    let app = TestApp::new().await;

    let username = "some_random_username";
    let password = "some_random_password";

    // /user/register
    let res = app
        .http_client
        .post(format!("{}/user/register", app.base_url))
        .json(&json!({
            "username": username,
            "password": password
        }))
        .send()
        .await
        .expect("Failed to send register user request");

    // make sure the operation success
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "Register response status is not 201 CREATED, response={}",
        res.text().await.expect("Failed to recv res body")
    );

    // create another user with the same username but uppercased
    let username = username.to_uppercase();
    let res = app
        .http_client
        .post(format!("{}/user/register", app.base_url))
        .json(&json!({
            "username": username,
            "password": password
        }))
        .send()
        .await
        .expect("Failed to send register user request");

    // make sure the operation success
    assert_eq!(
        res.status(),
        StatusCode::CONFLICT,
        "Register response status is not 409 CONFLICT, response={}",
        res.text().await.expect("Failed to recv res body")
    );
}

#[tokio::test]
async fn register_user_failure_when_no_password_provided() {
    let app = TestApp::new().await;

    let username = "some_random_username";
    let password = ""; // this is empty

    // /user/register
    let res = app
        .http_client
        .post(format!("{}/user/register", app.base_url))
        .json(&json!({
            "username": username,
            "password": password
        }))
        .send()
        .await
        .expect("Failed to send register user request");

    // make sure the response code is 201 Created
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "Register response status is not 400 BAD_REQUEST, response={}",
        res.text().await.expect("Failed to recv res body")
    );

    // make sure no user was created in the database
    let user_option = sqlx::query!("SELECT (id) FROM users WHERE username = $1", username)
        .fetch_optional(&app.db)
        .await
        .expect("Failed to query db");

    assert!(
        user_option.is_none(),
        "Service should not create user when the request fails, expected None on variable user_option",
    );
}

#[tokio::test]
async fn login_success_with_correct_credentials_provided() {
    let app = TestApp::new().await;

    let username = app.test_user.username;
    let password = app.test_user.password;

    // we can use the test_user now
    // login with the test_user credentials
    let res = app
        .http_client
        .post(format!("{}/user/login", app.base_url))
        .json(&json!({
            "username": username,
            "password": password
        }))
        .send()
        .await
        .expect("Failed to send login request");

    // the status code should be 200 OK
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "Login status code is not 200 OK"
    );

    // the access_token and refresh_token field should exist in the response body
    let body: serde_json::Value = res
        .json()
        .await
        .expect("Failed to receive login response body");

    assert!(body.is_object(), "Response body should be an object");
    let body = body.as_object().unwrap();
    assert!(
        body.contains_key("access_token"),
        "No access_token field exists in auth response. response={:?}",
        body
    );
    assert!(
        body.contains_key("refresh_token"),
        "No refresh_token field exists in auth response. response={:?}",
        body
    );
}

#[tokio::test]
async fn login_failure_with_incorrect_credentials_provided() {
    let app = TestApp::new().await;

    let username = app.test_user.username;
    let password = "not_the_correct_password";

    // we can use the test_user now
    // login with the test_user credentials
    let res = app
        .http_client
        .post(format!("{}/user/login", app.base_url))
        .json(&json!({
            "username": username,
            "password": password
        }))
        .send()
        .await
        .expect("Failed to send login request");

    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "Login status code is not 401 UNAUTHORIZED"
    );
}

#[tokio::test]
async fn login_failure_with_no_existent_user() {
    let app = TestApp::new().await;

    let username = "not_exist";
    let password = "not_the_correct_password";

    // we can use the test_user now
    // login with the test_user credentials
    let res = app
        .http_client
        .post(format!("{}/user/login", app.base_url))
        .json(&json!({
            "username": username,
            "password": password
        }))
        .send()
        .await
        .expect("Failed to send login request");

    // Note: this should be no differance with the incorrect password path
    // for increment security.
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "Login status code is not 401 UNAUTHORIZED"
    );
}

#[tokio::test]
async fn refresh_success_with_valid_refresh_token() {
    let app = TestApp::new().await;

    // authorize the test user first
    let credentials = app.auth_test_user().await;

    // refresh the token
    let res = app
        .http_client
        .post(format!("{}/user/refresh", app.base_url))
        .json(&json!({
            "refresh_token": credentials.refresh_token,
        }))
        .send()
        .await
        .expect("Failed to send refresh request");

    assert_eq!(
        res.status(),
        StatusCode::OK,
        "Refresh API status code is not 200 OK"
    );

    // the access_token and refresh_token field should exist in the response body
    let body: serde_json::Value = res
        .json()
        .await
        .expect("Failed to receive login response body");

    assert!(body.is_object(), "Response body should be an object");
    let body = body.as_object().unwrap();
    assert!(
        body.contains_key("access_token"),
        "No access_token field exists in auth response. response={:?}",
        body
    );
    assert!(
        body.contains_key("refresh_token"),
        "No refresh_token field exists in auth response. response={:?}",
        body
    );

    // the old refresh token should be revoked, expected 401 UNAUTHORIZED
    let res = app
        .http_client
        .post(format!("{}/user/refresh", app.base_url))
        .json(&json!({
            "refresh_token": credentials.refresh_token,
        }))
        .send()
        .await
        .expect("Failed to send refresh request");

    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "Refresh API status code is not 401 UNAUTHORIZED"
    );
}

#[tokio::test]
async fn refresh_failure_with_invalid_jwt() {
    let app = TestApp::new().await;

    // refresh the token
    let res = app
        .http_client
        .post(format!("{}/user/refresh", app.base_url))
        .json(&json!({
            "refresh_token": "lol it is invalid",
        }))
        .send()
        .await
        .expect("Failed to send refresh request");

    // Why this returns 400 not 401?
    // The service logic checks the jwt validation before refresh, if the check fails, the api
    // will returns 400 BAD_REQUEST instead of 401 UNAUTHORIZED.
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "Refresh API status code is not 400 BAD_REQUEST"
    );

    // try to refresh with a jwt that is not an refresh token
    let credentials = app.auth_test_user().await;

    // refresh the token
    let res = app
        .http_client
        .post(format!("{}/user/refresh", app.base_url))
        .json(&json!({
            "refresh_token": credentials.access_token, // this 100% not a refresh token
        }))
        .send()
        .await
        .expect("Failed to send refresh request");

    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "Refresh API status code is not 401 UNAUTHORIZED"
    );
}
