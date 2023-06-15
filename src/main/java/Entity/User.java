package Entity;

import org.mindrot.jbcrypt.BCrypt;

public class User {

    private String userName;

    private String UserPassword;

    public User() {}

    public boolean verifyPassword(String password){
        return (BCrypt.checkpw(password,UserPassword));
    }

    public User(String userName, String userPassword) {
        this.userName = userName;
        UserPassword = BCrypt.hashpw(userPassword,BCrypt.gensalt());
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getUserPassword() {
        return UserPassword;
    }

    public void setUserPassword(String userPassword) {
        UserPassword = userPassword;
    }

    @Override
    public String toString() {
        return "User{" +
                "userName='" + userName + '\'' +
                ", UserPassword='" + UserPassword + '\'' +
                '}';
    }
}
