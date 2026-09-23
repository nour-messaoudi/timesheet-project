package tn.esprit.spring.control;

import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import tn.esprit.spring.entities.User;
import tn.esprit.spring.services.IUserService;

@WebMvcTest(UserRestController.class)
class UserRestControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private IUserService userService;

    @Test
    void addUserWithMissingFieldsMustBeRejected() throws Exception {

        mockMvc.perform(
                post("/user/add-user")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}")
        )
        .andExpect(status().isBadRequest());

        verifyNoInteractions(userService);
    }

    @Test
    void retrieveUserWithTamperedIdMustBeRejected() throws Exception {

        mockMvc.perform(
                get("/user/retrieve-user/abc")
        )
        .andExpect(status().isBadRequest());

        verifyNoInteractions(userService);
    }

    @Test
    void retrieveNonExistingUserMustReturnNotFound() throws Exception {

        when(userService.retrieveUser("999999"))
                .thenReturn(null);

        mockMvc.perform(
                get("/user/retrieve-user/999999")
        )
        .andExpect(status().isNotFound());
    }

    @Test
    void retrieveExistingUserMustReturnOk() throws Exception {

        User user = new User(
                "John",
                "Doe",
                "USER",
                new java.util.Date()
        );

        when(userService.retrieveUser("1"))
                .thenReturn(user);

        mockMvc.perform(
                get("/user/retrieve-user/1")
        )
        .andExpect(status().isOk());
    }
}
