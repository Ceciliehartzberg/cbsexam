package controllers;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;

import cache.UserCache;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import model.User;
import utils.Hashing;
import utils.Log;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTCreationException;

public class UserController {

  private static DatabaseController dbCon;

  public UserController() {
    dbCon = new DatabaseController();
  }

  public static User getUser(int id) {

    // Check for connection
    if (dbCon == null) {
      dbCon = new DatabaseController();
    }

    // Build the query for DB
    String sql = "SELECT * FROM user where id=" + id;

    UserCache userCache = new UserCache();
    userCache.getUsers(true);

    // Actually do the query
    ResultSet rs = dbCon.query(sql);
    User user = null;

    try {
      // Get first object, since we only have one
      if (rs.next()) {
        user =
                new User(
                        rs.getInt("id"),
                        rs.getString("first_name"),
                        rs.getString("last_name"),
                        rs.getString("password"),
                        rs.getString("email"));

        // return the create object
        return user;
      } else {
        System.out.println("No user found");
      }
    } catch (SQLException ex) {
      System.out.println(ex.getMessage());
    }

    // Return null
    return user;
  }

  public static String getLogin(User user) {

    // Check for connection
    if (dbCon == null) {
      dbCon = new DatabaseController();
    }

    // Build the query for DB
    String sql = "SELECT * FROM user where email=" + user.getEmail() + "AND password" + Hashing.shaSalt(user.getPassword());

    // Actually do the query
    ResultSet rs = dbCon.query(sql);
    User loginUser = null;

    String token = null;

    try {
      // Get first object, since we only have one
      if (rs.next()) {
        user =
                new User(
                        rs.getInt("id"),
                        rs.getString("first_name"),
                        rs.getString("last_name"),
                        rs.getString("password"),
                        rs.getString("email"));

        // return the create object
        if (loginUser != null) {
          try {
            Algorithm algorithm = Algorithm.HMAC256("secret");
            token = JWT.create()
                    .withClaim("userId", user.getId())
                    .withIssuer("auth0")
                    .sign(algorithm);
          } catch (JWTCreationException exception) {
            //Invalid Signing configuration / Couldn't convert Claims.
          } finally {
            return token;
          }
        }
      } else {
        System.out.println("No user found");
      }
    } catch (SQLException ex) {
      System.out.println(ex.getMessage());
    }

    // Return null
    return "";
  }

  /**
   * Get all users in database
   *
   * @return
   */
  public static ArrayList<User> getUsers() {

    // Check for DB connection
    if (dbCon == null) {
      dbCon = new DatabaseController();
    }

    // Build SQL
    String sql = "SELECT * FROM user";

    // Do the query and initialyze an empty list for use if we don't get results
    ResultSet rs = dbCon.query(sql);
    ArrayList<User> users = new ArrayList<User>();

    try {
      // Loop through DB Data
      while (rs.next()) {
        User user =
                new User(
                        rs.getInt("id"),
                        rs.getString("first_name"),
                        rs.getString("last_name"),
                        rs.getString("password"),
                        rs.getString("email"));

        // Add element to list
        users.add(user);
      }
    } catch (SQLException ex) {
      System.out.println(ex.getMessage());
    }

    // Return the list of users
    return users;
  }

  public static User createUser(User user) {

    // Write in log that we've reach this step
    Log.writeLog(UserController.class.getName(), user, "Actually creating a user in DB", 0);

    // Set creation time for user.
    user.setCreatedTime(System.currentTimeMillis() / 1000L);

    // Check for DB Connection
    if (dbCon == null) {
      dbCon = new DatabaseController();
    }

    // Insert the user in the DB
    // TODO: Hash the user password before saving it. FIXED
    int userID = dbCon.insert(
            "INSERT INTO user(first_name, last_name, password, email, created_at) VALUES('"
                    + user.getFirstname()
                    + "', '"
                    + user.getLastname()
                    + "', '"
                    + Hashing.shaSalt(user.getPassword())
                    + "', '"
                    + user.getEmail()
                    + "', "
                    + user.getCreatedTime()
                    + ")");

    if (userID != 0) {
      //Update the userid of the user before returning
      user.setId(userID);
    } else {
      // Return null if user has not been inserted into database
      return null;
    }

    // Return user
    return user;
  }

  public static User deleteUser(User user) {
    if (dbCon == null) {
      dbCon = new DatabaseController();
    }

    try {
      PreparedStatement deleteUser = dbCon.getConnection().prepareStatement("DELETE FROM user WHERE id= ?");
      deleteUser.setInt(1, user.getId());

      deleteUser.executeUpdate();
    } catch (SQLException sql){
      sql.getStackTrace();
    }
    return user;
    }

  public static String getTokenVerifier(User user) {
    //Checking for connection to DB
    if (dbCon == null) {
      dbCon = new DatabaseController();

    }
    //building the query for DB
    String sql = "SELECT * FROM user WHERE id=" + user.getId();

    // this is where the query executes
    ResultSet rs = dbCon.query(sql);
    User sessionToken;
    String token = user.getToken();

    try {
      // Get first object since we only have one
      if (rs.next()) {
        sessionToken =
                new User(
                        rs.getInt("id"),
                        rs.getString("first name"),
                        rs.getString("last name"),
                        rs.getString("password"),
                        rs.getString("email"));
        if (sessionToken != null) {
          try {
            Algorithm algorithm = Algorithm.HMAC256("secret");
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer("aut0")
                    .build();
            DecodedJWT jwt = verifier.verify(token);
            Claim claim = jwt.getClaim("userId");

            if (user.getId() == claim.asInt()) {
              return token;
            }

          } catch (JWTVerificationException e) {
            System.out.println(e.getMessage());
            //invalid singing configuration / could not convert claims
          }
        }
      } else {
        System.out.println("No user found");
      }
    } catch (SQLException ex) {
      System.out.println(ex.getMessage());
    }
    //return null
    return ("");
  }
  public static  User update (User user) {
    // check for DB connection
    if ( (dbCon==null)) {
      dbCon= new DatabaseController();
    }
    try {
      PreparedStatement updateUser = dbCon.getConnection().prepareStatement("UPDATE user SET first_name = ?, last_name = ?, email = ? WHERE id ? ?");

      updateUser.setString(1, user.getFirstname());
      updateUser.setString(2, user.getLastname());
      updateUser.setString(3, Hashing.shaSalt(user.getPassword()));
      updateUser.setString(4, user.getEmail());
      updateUser.setInt(5, user.getId());

      updateUser.executeUpdate();

    } catch (SQLException e){
      e.printStackTrace();
    }
    return user;
  }

  }

