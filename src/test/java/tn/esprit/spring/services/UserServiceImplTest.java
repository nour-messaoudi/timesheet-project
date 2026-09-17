package tn.esprit.spring.services;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import tn.esprit.spring.entities.User;
import tn.esprit.spring.repository.UserRepository;

@ExtendWith(MockitoExtension.class)
class UserServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserServiceImpl userService;

    private User user;
    private User user2;

    @BeforeEach
    void setUp() {

        user = new User(
                "Nour",
                "Messaoudi",
                "ADMIN",
                null
        );

        user.setId(1L);

        user2 = new User(
                "Test",
                "User",
                "USER",
                null
        );

        user2.setId(2L);
    }

    @Test
    void testRetrieveAllUsers() {

        when(userRepository.findAll())
                .thenReturn(Arrays.asList(user, user2));

        List<User> result = userService.retrieveAllUsers();

        assertNotNull(result);
        assertEquals(2, result.size());
        assertEquals(user, result.get(0));
        assertEquals(user2, result.get(1));

        verify(userRepository, times(1)).findAll();
    }

    @Test
    void testRetrieveAllUsersWhenRepositoryThrowsException() {

        when(userRepository.findAll())
                .thenThrow(new RuntimeException("Database error"));

        List<User> result = userService.retrieveAllUsers();

        assertNull(result);

        verify(userRepository, times(1)).findAll();
    }

    @Test
    void testAddUser() {

        when(userRepository.save(user))
                .thenReturn(user);

        User result = userService.addUser(user);

        assertNotNull(result);
        assertEquals(user, result);

        verify(userRepository, times(1)).save(user);
    }

    @Test
    void testAddUserWhenRepositoryThrowsException() {

        when(userRepository.save(user))
                .thenThrow(new RuntimeException("Database error"));

        User result = userService.addUser(user);

        assertNull(result);

        verify(userRepository, times(1)).save(user);
    }

    @Test
    void testUpdateUser() {

        when(userRepository.save(user))
                .thenReturn(user);

        User result = userService.updateUser(user);

        assertNotNull(result);
        assertEquals(user, result);

        verify(userRepository, times(1)).save(user);
    }

    @Test
    void testUpdateUserWhenRepositoryThrowsException() {

        when(userRepository.save(user))
                .thenThrow(new RuntimeException("Database error"));

        User result = userService.updateUser(user);

        assertNull(result);

        verify(userRepository, times(1)).save(user);
    }

    @Test
    void testRetrieveUser() {

        when(userRepository.findById(1L))
                .thenReturn(Optional.of(user));

        User result = userService.retrieveUser("1");

        assertNotNull(result);
        assertEquals(user, result);

        verify(userRepository, times(1)).findById(1L);
    }

    @Test
    void testRetrieveUserWhenUserDoesNotExist() {

        when(userRepository.findById(1L))
                .thenReturn(Optional.empty());

        User result = userService.retrieveUser("1");

        assertNull(result);

        verify(userRepository, times(1)).findById(1L);
    }

    @Test
    void testRetrieveUserWithInvalidId() {

        User result = userService.retrieveUser("invalid");

        assertNull(result);

        verify(userRepository, never()).findById(anyLong());
    }

    @Test
    void testDeleteUser() {

        doNothing()
                .when(userRepository)
                .deleteById(1L);

        assertDoesNotThrow(() ->
                userService.deleteUser("1")
        );

        verify(userRepository, times(1))
                .deleteById(1L);
    }

    @Test
    void testDeleteUserWhenRepositoryThrowsException() {

        doThrow(new RuntimeException("Database error"))
                .when(userRepository)
                .deleteById(1L);

        assertDoesNotThrow(() ->
                userService.deleteUser("1")
        );

        verify(userRepository, times(1))
                .deleteById(1L);
    }

    @Test
    void testDeleteUserWithInvalidId() {

        assertDoesNotThrow(() ->
                userService.deleteUser("invalid")
        );

        verify(userRepository, never())
                .deleteById(anyLong());
    }
}
