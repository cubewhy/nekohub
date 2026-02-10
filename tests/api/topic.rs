use reqwest::StatusCode;
use serde_json::json;

use crate::helpers::{TestApp, UserCredentials};

#[tokio::test]
async fn create_topic_success_with_valid_data() {
    let app = TestApp::new().await;

    // authorize test user
    let UserCredentials { access_token, .. } = app.auth_test_user().await;

    let post_title = "Hello World";
    let post_content = "Welcome to nekohub!";
    let post_tags = vec!["test"];

    // /topics/new
    let res = app
        .http_client
        .post(format!("{}/topics/new", app.base_url))
        .json(&json!({
            "title": post_title,
            "content": post_content,
            "tags": post_tags,
        }))
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await
        .expect("Failed to send create topic request");

    // res status should be 201 CREATED
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "Response code is not 201 CREATED"
    );

    let body = res
        .json::<serde_json::Value>()
        .await
        .expect("Failed to receive response json");
    assert!(
        body.is_object(),
        "Response body is not an object, response={body}"
    );
    let body = body.as_object().unwrap();

    // response should contains the topic id
    assert!(
        body.contains_key("id"),
        "No id field found in response, response={body:?}"
    );

    // response should contains initial post data
    assert!(
        body.contains_key("initial_post"),
        "No initial_post id field found in response, response={body:?}"
    );

    // We don't verify the data inside initial_post field because the server might do filter/format
    // on the post content which is sometimes unpredictable
}

#[tokio::test]
async fn reply_success_with_valid_topic() {
    let app = TestApp::new().await;

    let UserCredentials { access_token, .. } = app.auth_test_user().await;

    // create the topic
    let topic = app
        .create_topic(
            &access_token,
            "Test Topic",
            "LGTM",
            vec!["test".to_string()],
        )
        .await;

    // reply the topic
    let res = app
        .http_client
        .post(format!(
            "{}/topics/{}/reply",
            app.base_url, topic.initial_post.id
        ))
        .json(&json!({
            "content": "LGTM too!"
        }))
        .send()
        .await
        .expect("Failed to reply to post");

    // res status should be 201 CREATED
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "Response code is not 201 CREATED"
    );

    let body = res
        .json::<serde_json::Value>()
        .await
        .expect("Failed to receive response json");
    assert!(
        body.is_object(),
        "Response body is not an object, response={body}"
    );
    let body = body.as_object().unwrap();

    assert!(
        body.contains_key("id"),
        "Response body doesn't contains id, response={body:?}"
    );
    assert!(
        body.contains_key("content"),
        "Response body doesn't contains content, response={body:?}"
    );
}
