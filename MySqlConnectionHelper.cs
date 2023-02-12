using MySql.Data.MySqlClient;

namespace dotnet_test_app
{
    public class MySqlConnectionHelper
    {
        public static MySqlConnection GetConnection()
        {
            string connectionString = "Server=173.254.39.157;Database=hzmnrnmy_test-mysql;Uid=hzmnrnmy_usrtest;Pwd=Mercerst.13;";
            MySqlConnection connection = new MySqlConnection(connectionString);
            connection.Open();
            return connection;
        }
    }
}
