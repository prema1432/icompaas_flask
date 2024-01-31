import pytest
from flask import json
from app import app


def test_sanitized_input():
    """Test with a sanitized input."""
    url = '/v1/sanitized/input/'

    # Test with a sanitized input
    data = {'input': 'safe_input'}
    response = app.test_client().post(url, data=json.dumps(data), content_type='application/json')

    assert response.status_code == 200
    assert json.loads(response.data)['result'] == 'sanitized'


def test_unsanitized_input():
    """Test with an unsanitized input."""
    url = '/v1/sanitized/input/'

    # Test with an unsanitized input
    data = {'input': 'unsafe_input; DROP TABLE users;'}
    response = app.test_client().post(url, data=json.dumps(data), content_type='application/json')

    assert response.status_code == 200
    assert json.loads(response.data)['result'] == 'unsanitized'


def test_missing_input():
    """Test with missing input."""
    url = '/v1/sanitized/input/'
    data = {}
    # Test with missing input
    response = app.test_client().post(url, data=json.dumps(data), content_type='application/json')

    assert response.status_code == 200
    assert json.loads(response.data)['result'] == 'sanitized'


def test_sql_injection_attempt():
    """Test with a SQL injection attempt."""
    url = '/v1/sanitized/input/'

    # Test with a SQL injection attempt
    user_input = "'; DROP TABLE users; --"
    data = {'input': user_input}
    response = app.test_client().post(url, data=json.dumps(data), content_type='application/json')

    assert response.status_code == 200
    assert json.loads(response.data)['result'] == 'unsanitized'


def test_union_based_sql_injection():
    """Test with a Union-based SQL injection attempt."""
    url = '/v1/sanitized/input/'

    # Test with a Union-based SQL injection attempt
    user_input = "1 UNION SELECT username, password FROM users --"
    data = {'input': user_input}
    response = app.test_client().post(url, data=json.dumps(data), content_type='application/json')

    assert response.status_code == 200
    assert json.loads(response.data)['result'] == 'unsanitized'


def test_boolean_based_sql_injection():
    """Test with a Boolean-based Blind SQL injection attempt."""
    url = '/v1/sanitized/input/'

    # Test with a Boolean-based Blind SQL injection attempt
    user_input = "admin' AND 1=1 --"
    data = {'input': user_input}
    response = app.test_client().post(url, data=json.dumps(data), content_type='application/json')

    assert response.status_code == 200
    assert json.loads(response.data)['result'] == 'unsanitized'


def test_time_based_sql_injection():
    """Test with a Time-based Blind SQL injection attempt."""
    url = '/v1/sanitized/input/'

    # Test with a Time-based Blind SQL injection attempt
    user_input = "admin' AND IF(1=1, SLEEP(5), 0) --"
    data = {'input': user_input}
    response = app.test_client().post(url, data=json.dumps(data), content_type='application/json')

    assert response.status_code == 200
    assert json.loads(response.data)['result'] == 'unsanitized'


def test_xss_attempt():
    """Test with a Cross-Site Scripting (XSS) attempt."""
    url = '/v1/sanitized/input/'

    # Test with a Cross-Site Scripting (XSS) attempt
    user_input = "<script>alert('XSS');</script>"
    data = {'input': user_input}
    response = app.test_client().post(url, data=json.dumps(data), content_type='application/json')

    assert response.status_code == 200
    assert json.loads(response.data)['result'] == 'unsanitized'


def test_sanitized_input_numbers():
    """Test that input containing only numbers is sanitized."""
    url = '/v1/sanitized/input/'

    # Test with a sanitized input containing only numbers
    user_input = "12345"
    data = {'input': user_input}
    response = app.test_client().post(url, data=json.dumps(data), content_type='application/json')

    assert response.status_code == 200
    assert json.loads(response.data)['result'] == 'sanitized'


def test_sanitized_input_characters():
    """Test that input containing only characters is sanitized."""
    url = '/v1/sanitized/input/'

    # Test with a sanitized input containing only characters
    user_input = "abcde"
    data = {'input': user_input}
    response = app.test_client().post(url, data=json.dumps(data), content_type='application/json')

    assert response.status_code == 200
    assert json.loads(response.data)['result'] == 'sanitized'


def test_sanitized_input_numbers_and_characters():
    """Test that input containing only numbers and characters is sanitized."""
    url = '/v1/sanitized/input/'
    user_input = "a1b2c3"
    data = {'input': user_input}
    response = app.test_client().post(url, data=json.dumps(data), content_type='application/json')

    assert response.status_code == 200
    assert json.loads(response.data)['result'] == 'sanitized'


def test_unsanitized_input_special_characters():
    """Test with an unsanitized input containing special characters."""
    url = '/v1/sanitized/input/'

    # Test with an unsanitized input containing special characters
    user_input = "!@#$%^&*"
    data = {'input': user_input}
    response = app.test_client().post(url, data=json.dumps(data), content_type='application/json')

    assert response.status_code == 200
    assert json.loads(response.data)['result'] == 'unsanitized'


def test_unsanitized_input_numbers_and_special_characters():
    """Test with an unsanitized input containing numbers and special characters."""
    url = '/v1/sanitized/input/'
    user_input = "123!@#"
    data = {'input': user_input}
    response = app.test_client().post(url, data=json.dumps(data), content_type='application/json')

    assert response.status_code == 200
    assert json.loads(response.data)['result'] == 'unsanitized'
