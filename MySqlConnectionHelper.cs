using MySql.Data.MySqlClient;
using MySqlX.XDevAPI;

namespace dotnet_test_app
{
    public class MySqlConnectionHelper
    {
        public static MySqlConnection GetConnection()
        {
            var configuration = new ConfigurationBuilder()
                 .AddJsonFile("appsettings.json")
                 .AddEnvironmentVariables()
                 .Build();

            var server = configuration["SERVER"];
            var database = configuration["DATABASE"];
            var uid = configuration["USERNAME"];
            var pwd = configuration["PASSWORD"];

            string connectionString = $"Server={server};Database={database};Uid={uid};Pwd={pwd};";
            MySqlConnection connection = new MySqlConnection(connectionString);
            connection.Open();
            return connection;
        }
    }
}
