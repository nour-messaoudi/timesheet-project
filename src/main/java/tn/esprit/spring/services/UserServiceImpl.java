package tn.esprit.spring.services;

import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import tn.esprit.spring.entities.User;
import tn.esprit.spring.repository.UserRepository;

@Service
public class UserServiceImpl implements IUserService {

    @Autowired
    UserRepository userRepository;

    private static final Logger l = LogManager.getLogger(UserServiceImpl.class);

    @Override
    public List<User> retrieveAllUsers() {
        try {
            return userRepository.findAll();
        } catch (Exception e) {
            l.error("Error in retrieveAllUsers()", e);
            return null;
        }
    }

    @Override
    public User addUser(User u) {
        try {
            return userRepository.save(u);
        } catch (Exception e) {
            l.error("Error in addUser()", e);
            return null;
        }
    }

    @Override
    public User updateUser(User u) {
        try {
            return userRepository.save(u);
        } catch (Exception e) {
            l.error("Error in updateUser()", e);
            return null;
        }
    }

    @Override
    public void deleteUser(String id) {
        try {
            userRepository.deleteById(Long.parseLong(id));
        } catch (Exception e) {
            l.error("Error in deleteUser()", e);
        }
    }

    @Override
    public User retrieveUser(String id) {
        try {
            return userRepository.findById(Long.parseLong(id)).orElse(null);
        } catch (Exception e) {
            l.error("Error in retrieveUser()", e);
            return null;
        }
    }
}
