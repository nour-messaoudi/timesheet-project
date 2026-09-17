package tn.esprit.spring.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
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

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserServiceImpl userService;

    private User user;

    @BeforeEach
    void setUp() {
        user = new User(
                "Nour",
                "Messaoudi",
                "ADMIN",
                new Date()
        );
    }

    @Test
    void testRetrieveAllUsers() {

        List<User> users = Arrays.asList(user);

        when(userRepository.findAll()).thenReturn(users);

        List<User> result = userService.retrieveAllUsers();

        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals(users, result);

        verify(userRepository).findAll();
    }

    @Test
    void testRetrieveAllUsersWhenRepositoryReturnsEmptyList() {

        when(userRepository.findAll())
                .thenReturn(Collections.emptyList());

        List<User> result = userService.retrieveAllUsers();

        assertNotNull(result);
        assertTrue(result.isEmpty());

        verify(userRepository).findAll();
    }

    @Test
    void testRetrieveAllUsersWhenRepositoryThrowsException() {

        when(userRepository.findAll())
                .thenThrow(new RuntimeException("Database error"));

        List<User> result = userService.retrieveAllUsers();

        assertNotNull(result);
        assertTrue(result.isEmpty());

        verify(userRepository).findAll();
    }

    @Test
    void testAddUser() {

        when(userRepository.save(user))
                .thenReturn(user);

        User result = userService.addUser(user);

        assertNotNull(result);
        assertEquals(user, result);

        verify(userRepository).save(user);
    }

    @Test
    void testAddUserWhenRepositoryThrowsException() {

        when(userRepository.save(user))
                .thenThrow(new RuntimeException("Database error"));

        User result = userService.addUser(user);

        assertNull(result);

        verify(userRepository).save(user);
    }

    @Test
    void testUpdateUser() {

        when(userRepository.save(user))
                .thenReturn(user);

        User result = userService.updateUser(user);

        assertNotNull(result);
        assertEquals(user, result);

        verify(userRepository).save(user);
    }

    @Test
    void testUpdateUserWhenRepositoryThrowsException() {

        when(userRepository.save(user))
                .thenThrow(new RuntimeException("Database error"));

        User result = userService.updateUser(user);

        assertNull(result);

        verify(userRepository).save(user);
    }

    @Test
    void testRetrieveUser() {

        when(userRepository.findById(1L))
                .thenReturn(Optional.of(user));

        User result = userService.retrieveUser("1");

        assertNotNull(result);
        assertEquals(user, result);

        verify(userRepository).findById(1L);
    }

    @Test
    void testRetrieveUserWhenUserDoesNotExist() {

        when(userRepository.findById(1L))
                .thenReturn(Optional.empty());

        User result = userService.retrieveUser("1");

        assertNull(result);

        verify(userRepository).findById(1L);
    }

    @Test
    void testRetrieveUserWithInvalidId() {

        User result = userService.retrieveUser("invalid");

        assertNull(result);
    }

    @Test
    void testDeleteUser() {

        assertDoesNotThrow(() ->
                userService.deleteUser("1")
        );

        verify(userRepository).deleteById(1L);
    }

    @Test
    void testDeleteUserWhenRepositoryThrowsException() {

        doThrow(new RuntimeException("Database error"))
                .when(userRepository)
                .deleteById(1L);

        assertDoesNotThrow(() ->
                userService.deleteUser("1")
        );

        verify(userRepository).deleteById(1L);
    }

    @Test
    void testDeleteUserWithInvalidId() {

        assertDoesNotThrow(() ->
                userService.deleteUser("invalid")
        );
    }

    @Test
    void testAddUserWithNullResult() {

        when(userRepository.save(user))
                .thenReturn(null);

        User result = userService.addUser(user);

        assertNull(result);

        verify(userRepository).save(user);
    }

    @Test
    void testUpdateUserWithNullResult() {

        when(userRepository.save(user))
                .thenReturn(null);

        User result = userService.updateUser(user);

        assertNull(result);

        verify(userRepository).save(user);
    }
}
