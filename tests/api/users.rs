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

    // make sure there is an username field in the response
    let res_json: serde_json::Value = res
        .json()
        .await
        .expect("Failed to receive register response json");

    assert!(res_json.is_object(), "Response json is not an object");
    assert!(
        res_json.as_object().unwrap().contains_key("username"),
        "Response json doesn't contains the username field"
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
