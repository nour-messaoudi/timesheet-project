package tn.esprit.spring.control;

import java.util.List;

import org.springframework.web.bind.annotation.*;

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
    public List<User> retrieveAllUsers() {
        return userService.retrieveAllUsers();
    }

    @GetMapping("/retrieve-user/{user-id}")
    public User retrieveUser(@PathVariable("user-id") String userId) {
        return userService.retrieveUser(userId);
    }

    @PostMapping("/add-user")
    public User addUser(@RequestBody User u) {
        return userService.addUser(u);
    }
}
