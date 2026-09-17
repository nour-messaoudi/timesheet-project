package tn.esprit.spring.dto;

import java.util.Date;

public class UserDTO {

    private Long id;
    private String firstName;
    private String lastName;
    private String role;
    private Date dateNaissance;

    public UserDTO() {
    }

    public UserDTO(
            Long id,
            String firstName,
            String lastName,
            String role,
            Date dateNaissance) {

        this.id = id;
        this.firstName = firstName;
        this.lastName = lastName;
        this.role = role;
        this.dateNaissance = dateNaissance;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public Date getDateNaissance() {
        return dateNaissance;
    }

    public void setDateNaissance(Date dateNaissance) {
        this.dateNaissance = dateNaissance;
    }
}
