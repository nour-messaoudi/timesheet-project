package tn.esprit.spring.control;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import tn.esprit.spring.dto.UserDTO;
import tn.esprit.spring.entities.User;
import tn.esprit.spring.services.IUserService;

@RestController
@RequestMapping("/user")
public class UserRestController {

    private final IUserService userService;

    public UserRestController(IUserService userService) {
        this.userService = userService;
    }

    @GetMapping("/retrieve-all-users")
    public List<UserDTO> retrieveAllUsers() {

        return userService.retrieveAllUsers()
                .stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    @GetMapping("/retrieve-user/{user-id}")
    public UserDTO retrieveUser(
            @PathVariable("user-id") String userId) {

        User user = userService.retrieveUser(userId);

        if (user == null) {
            return null;
        }

        return convertToDTO(user);
    }

    @PostMapping("/add-user")
    public UserDTO addUser(@RequestBody UserDTO userDTO) {

        User user = convertToEntity(userDTO);

        User savedUser = userService.addUser(user);

        if (savedUser == null) {
            return null;
        }

        return convertToDTO(savedUser);
    }

    private UserDTO convertToDTO(User user) {

        return new UserDTO(
                user.getId(),
                user.getFirstName(),
                user.getLastName(),
                user.getRole(),
                user.getDateNaissance()
        );
    }

    private User convertToEntity(UserDTO userDTO) {

        User user = new User();

        user.setId(userDTO.getId());
        user.setFirstName(userDTO.getFirstName());
        user.setLastName(userDTO.getLastName());
        user.setRole(userDTO.getRole());
        user.setDateNaissance(userDTO.getDateNaissance());

        return user;
    }
@GetMapping("/hello")
public String hello() {
    return "Hello from Timesheet DevOps! - Version 1";
}

}
