from flask import Flask, request, jsonify
import re

app = Flask(__name__)

def is_sanitized(input_string):
    """Return True if the input string is sanitized, False otherwise."""
    sql_injection_characters = [";", "--", "DROP", "DELETE", "INSERT", "UPDATE"]
    sql_injection_pattern = re.compile(r'[\;\*\|\'\"\=\(\)\[\]\{\}\%\@\,]')

    # Check for simple SQL injection characters
    for char in sql_injection_characters:
        if char in input_string:
            return False

    # Check for more complex SQL injection patterns using regular expression
    if sql_injection_pattern.search(input_string):
        return False

    return True

@app.route('/v1/sanitized/input/', methods=['POST'])
def sanitized_input():
    try:
        data = request.get_json()
        input_string = data.get('input', '')

        if not input_string:
            result = {"result": "sanitized"}
        elif is_sanitized(input_string):
            result = {"result": "sanitized"}
        else:
            result = {"result": "unsanitized"}

        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
