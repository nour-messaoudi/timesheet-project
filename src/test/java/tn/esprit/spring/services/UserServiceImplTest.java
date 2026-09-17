package tn.esprit.spring.services;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

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

import static org.mockito.ArgumentMatchers.any;
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

    // =========================================================
    // 1. retrieveAllUsers - SUCCESS
    // =========================================================

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

    // =========================================================
    // 2. retrieveAllUsers - EMPTY LIST
    // =========================================================

    @Test
    void testRetrieveAllUsersWhenRepositoryReturnsEmptyList() {

        when(userRepository.findAll())
                .thenReturn(Collections.emptyList());

        List<User> result = userService.retrieveAllUsers();

        assertNotNull(result);
        assertTrue(result.isEmpty());

        verify(userRepository).findAll();
    }

    // =========================================================
    // 3. retrieveAllUsers - EXCEPTION
    // =========================================================

    @Test
    void testRetrieveAllUsersWhenRepositoryThrowsException() {

        when(userRepository.findAll())
                .thenThrow(new RuntimeException("Database error"));

        List<User> result = userService.retrieveAllUsers();

        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    // =========================================================
    // 4. addUser - SUCCESS
    // =========================================================

    @Test
    void testAddUser() {

        when(userRepository.save(user))
                .thenReturn(user);

        User result = userService.addUser(user);

        assertNotNull(result);
        assertEquals(user, result);

        verify(userRepository).save(user);
    }

    // =========================================================
    // 5. addUser - EXCEPTION
    // =========================================================

    @Test
    void testAddUserWhenRepositoryThrowsException() {

        when(userRepository.save(user))
                .thenThrow(new RuntimeException("Database error"));

        User result = userService.addUser(user);

        assertNull(result);
    }

    // =========================================================
    // 6. updateUser - SUCCESS
    // =========================================================

    @Test
    void testUpdateUser() {

        when(userRepository.save(user))
                .thenReturn(user);

        User result = userService.updateUser(user);

        assertNotNull(result);
        assertEquals(user, result);

        verify(userRepository).save(user);
    }

    // =========================================================
    // 7. updateUser - EXCEPTION
    // =========================================================

    @Test
    void testUpdateUserWhenRepositoryThrowsException() {

        when(userRepository.save(user))
                .thenThrow(new RuntimeException("Database error"));

        User result = userService.updateUser(user);

        assertNull(result);
    }

    // =========================================================
    // 8. retrieveUser - SUCCESS
    // =========================================================

    @Test
    void testRetrieveUser() {

        when(userRepository.findById(1L))
                .thenReturn(Optional.of(user));

        User result = userService.retrieveUser("1");

        assertNotNull(result);
        assertEquals(user, result);

        verify(userRepository).findById(1L);
    }

    // =========================================================
    // 9. retrieveUser - USER NOT FOUND
    // =========================================================

    @Test
    void testRetrieveUserWhenUserDoesNotExist() {

        when(userRepository.findById(1L))
                .thenReturn(Optional.empty());

        User result = userService.retrieveUser("1");

        assertNull(result);

        verify(userRepository).findById(1L);
    }

    // =========================================================
    // 10. retrieveUser - INVALID ID
    // =========================================================

    @Test
    void testRetrieveUserWithInvalidId() {

        User result = userService.retrieveUser("invalid");

        assertNull(result);
    }

    // =========================================================
    // 11. deleteUser - SUCCESS
    // =========================================================

    @Test
    void testDeleteUser() {

        assertDoesNotThrow(() ->
                userService.deleteUser("1")
        );

        verify(userRepository).deleteById(1L);
    }

    // =========================================================
    // 12. deleteUser - EXCEPTION / INVALID ID
    // =========================================================

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
}
