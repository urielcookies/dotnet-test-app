using Microsoft.AspNetCore.Mvc;
using MySql.Data.MySqlClient;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace dotnet_test_app.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class MySqlTestController : ControllerBase
    {
        [HttpPost("login")]
        public IActionResult Login([FromBody] UserLogin user)
        {
            // Open a connection to the database
            using (var connection = MySqlConnectionHelper.GetConnection())
            {
                // Select the password for the user with the given email
                using (var command = new MySqlCommand("SELECT password FROM users WHERE email = @email", connection))
                {
                    command.Parameters.AddWithValue("@email", user.Email);

                    // Execute the query and get the reader
                    using (var reader = command.ExecuteReader())
                    {
                        // If there are no rows returned, the email is invalid
                        if (!reader.Read())
                        {
                            return BadRequest("Invalid email or password.");
                        }

                        // Get the hashed password from the reader
                        var passwordHash = reader.GetString(0);

                        // Verify that the given password matches the hashed password
                        if (!BCrypt.Net.BCrypt.Verify(user.Password, passwordHash))
                        {
                            return BadRequest("Invalid email or password.");
                        }
                    }
                }
            }

            // Create a JWT token handler
            var tokenHandler = new JwtSecurityTokenHandler();
            // The secret key used for signing the token
            var key = Encoding.ASCII.GetBytes("secret_key_that_needs_to_be_at_least_16_characters_long");
            // Define the token descriptor
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                // Set the subject to the email of the user
                Subject = new ClaimsIdentity(new Claim[]
                {
            new Claim(ClaimTypes.Email, user.Email.ToString())
                }),
                // Set the expiry date of the token to 7 days from now
                Expires = DateTime.UtcNow.AddDays(7),
                // Set the signing credentials for the token
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            // Create the token
            var token = tokenHandler.CreateToken(tokenDescriptor);
            // Write the token to a string
            var tokenString = tokenHandler.WriteToken(token);

            // Return the token to the client
            return Ok(new
            {
                Token = tokenString
            });
        }

        [Authorize]
        [HttpGet]
        public IActionResult Get()
        {
            // A list to hold all the records we retrieve from the database
            List<Dictionary<string, object>> records = new List<Dictionary<string, object>>();

            // Establish a connection to the database using the MySqlConnectionHelper
            using (MySqlConnection connection = MySqlConnectionHelper.GetConnection())
            {
                // Define the SQL query to retrieve data from the "users" table
                string query = "SELECT id, email, username FROM users";

                // Create a new MySqlCommand with the query and the connection
                MySqlCommand command = new MySqlCommand(query, connection);

                // Execute the command and retrieve the results as a reader
                using (MySqlDataReader reader = command.ExecuteReader())
                {
                    // Read through each row in the results
                    while (reader.Read())
                    {
                        // Create a new dictionary to hold the values for this row
                        Dictionary<string, object> record = new Dictionary<string, object>();

                        // Loop through each column in the row and add it to the dictionary
                        for (int i = 0; i < reader.FieldCount; i++)
                        {
                            record.Add(reader.GetName(i), reader[i]);
                        }

                        // Add the dictionary to the list of records
                        records.Add(record);
                    }
                }
            }

            // Return the list of records as a JSON response
            return Ok(records);
        }

        [Authorize]
        [HttpPost]
        public IActionResult Post([FromBody] Userr user)
        {
            // Check if the incoming user model is valid
            if (!ModelState.IsValid)
            {
                // If the model is not valid, return a Bad Request response with a message
                return BadRequest("Invalid model state");
            }

            // Hash the password using BCrypt
            string hashedPassword = BCryptHelper.HashPassword(user.Password, 12);

            // Open a new connection to the database
            using (MySqlConnection connection = MySqlConnectionHelper.GetConnection())
            {
                // Create a new SQL query to check if the email or username already exists
                string checkQuery = "SELECT * FROM users WHERE email = @Email OR username = @Username";
                MySqlCommand checkCommand = new MySqlCommand(checkQuery, connection);
                checkCommand.Parameters.AddWithValue("@Email", user.Email);
                checkCommand.Parameters.AddWithValue("@Username", user.Username);

                // Execute the query and create a reader to store the results
                using (MySqlDataReader checkReader = checkCommand.ExecuteReader())
                {
                    // If the query returns any results, it means that the email or username is already taken
                    if (checkReader.HasRows)
                    {
                        // Return a Bad Request response with a message
                        return BadRequest("Email or username already taken");
                    }
                }

                // Create a new SQL query to insert the user into the database
                string insertQuery = "INSERT INTO users (email, username, password) VALUES (@Email, @Username, @Password)";
                MySqlCommand insertCommand = new MySqlCommand(insertQuery, connection);
                insertCommand.Parameters.AddWithValue("@Email", user.Email);
                insertCommand.Parameters.AddWithValue("@Username", user.Username);
                insertCommand.Parameters.AddWithValue("@Password", hashedPassword);

                // Execute the insert query
                insertCommand.ExecuteNonQuery();
            }

            // Return a 201 Created response
            return StatusCode(201);
        }

        [Authorize]
        [HttpPut("{id}")]
        public IActionResult Put(int id, [FromBody] Userr user)
        {
            // Check if the incoming user model is valid
            if (!ModelState.IsValid)
            {
                // If the model is not valid, return a Bad Request response with a message
                return BadRequest("Invalid model state");
            }

            // Open a new connection to the database
            using (MySqlConnection connection = MySqlConnectionHelper.GetConnection())
            {
                // Create a new SQL query to check if the email or username already exists
                string checkQuery = "SELECT * FROM users WHERE (email = @Email OR username = @Username) AND id <> @Id";
                MySqlCommand checkCommand = new MySqlCommand(checkQuery, connection);
                checkCommand.Parameters.AddWithValue("@Email", user.Email);
                checkCommand.Parameters.AddWithValue("@Username", user.Username);
                checkCommand.Parameters.AddWithValue("@Id", id);

                // Execute the query and create a reader to store the results
                using (MySqlDataReader checkReader = checkCommand.ExecuteReader())
                {
                    // If the query returns any results, it means that the email or username is already taken
                    if (checkReader.HasRows)
                    {
                        // Return a Bad Request response with a message
                        return BadRequest("Email or username already taken");
                    }
                }

                // Hash the password using bcrypt
                string hashedPassword = BCrypt.Net.BCrypt.HashPassword(user.Password);

                // Create a new SQL query to update the user record in the database
                string updateQuery = "UPDATE users SET email = @Email, username = @Username, password = @Password WHERE id = @Id";
                MySqlCommand updateCommand = new MySqlCommand(updateQuery, connection);
                updateCommand.Parameters.AddWithValue("@Email", user.Email);
                updateCommand.Parameters.AddWithValue("@Username", user.Username);
                updateCommand.Parameters.AddWithValue("@Password", hashedPassword);
                updateCommand.Parameters.AddWithValue("@Id", id);

                // Execute the update query
                int rowsAffected = updateCommand.ExecuteNonQuery();

                // If no rows were affected, it means that the record was not found
                if (rowsAffected == 0)
                {
                    // Return a Not Found response
                    return NotFound();
                }
            }

            // Return a 204 No Content response
            return NoContent();
        }

        [Authorize]
        [HttpDelete("{id}")]
        public IActionResult Delete(int id)
        {
            // Open a new connection to the database
            using (MySqlConnection connection = MySqlConnectionHelper.GetConnection())
            {
                // Create a new SQL query to delete the user record with the given id
                string deleteQuery = "DELETE FROM users WHERE id = @Id";
                MySqlCommand deleteCommand = new MySqlCommand(deleteQuery, connection);
                deleteCommand.Parameters.AddWithValue("@Id", id);

                // Execute the delete query
                int rowsAffected = deleteCommand.ExecuteNonQuery();

                // If no rows were affected, it means that the record was not found
                if (rowsAffected == 0)
                {
                    // Return a Not Found response
                    return NotFound();
                }
            }

            // Return a 204 No Content response
            return NoContent();
        }

        public class Userr
        {
            public string? Id { get; set; }
            public string Username { get; set; }
            public string Password { get; set; }
            public string Email { get; set; }
        }
        public class UserLogin
        {
            public string Password { get; set; }
            public string Email { get; set; }
        }

        public static class BCryptHelper
        {
            public static string HashPassword(string password, int logRounds)
            {
                return BCrypt.Net.BCrypt.HashPassword(password, logRounds);
            }
        }
    }
}