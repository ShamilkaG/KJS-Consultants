package com.kjs.springjwt.controllers;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import javax.validation.Valid;

import com.kjs.springjwt.models.*;
import com.kjs.springjwt.payload.request.ChangePasswordRequest;
import com.kjs.springjwt.security.jwt.exception.TokenRefreshException;
import com.kjs.springjwt.payload.request.LoginRequest;
import com.kjs.springjwt.payload.request.SignupRequest;
import com.kjs.springjwt.payload.request.TokenRefreshRequest;
import com.kjs.springjwt.payload.response.JwtResponse;
import com.kjs.springjwt.payload.response.MessageResponse;
import com.kjs.springjwt.payload.response.TokenRefreshResponse;
import com.kjs.springjwt.repository.RoleRepository;
import com.kjs.springjwt.repository.UserRepository;
import com.kjs.springjwt.security.jwt.JwtUtils;
import com.kjs.springjwt.security.services.RefreshTokenService;
import com.kjs.springjwt.security.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    UserRepository userRepository;
    @Autowired
    RoleRepository roleRepository;
    @Autowired
    PasswordEncoder encoder;
    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    RefreshTokenService refreshTokenService;

    @Value("${kjs.app.user.reset.password}")
    private String resetPwd;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        String jwt = jwtUtils.generateJwtToken(userDetails);
        List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority())
                .collect(Collectors.toList());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());
        return ResponseEntity.ok(new JwtResponse(jwt, refreshToken.getToken(), userDetails.getId(),
                userDetails.getUsername(), userDetails.getEmail(), roles));
    }
    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshtoken(@Valid @RequestBody TokenRefreshRequest request) {
        String requestRefreshToken = request.getRefreshToken();
        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    String token = jwtUtils.generateTokenFromUsername(user.getUsername());
                    return ResponseEntity.ok(new TokenRefreshResponse(token, requestRefreshToken));
                })
                .orElseThrow(() -> new TokenRefreshException(requestRefreshToken,
                        "Refresh token is not in database!"));
    }
    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }
        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));
        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();
        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);
                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }
        user.setRoles(roles);
        userRepository.save(user);
        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @PostMapping("/changePassword")
    public ResponseEntity<?> changePassword( @RequestBody ChangePasswordRequest changePasswordRequest) {

        Object principal = SecurityContextHolder. getContext(). getAuthentication(). getPrincipal();
        String username;
        if (principal instanceof UserDetails) {
             username = ((UserDetails)principal). getUsername();
        } else {
             username = principal. toString();
        }

        Optional<User> userData = userRepository.findByUsername(username);
        if(userData.isPresent()){
            User _user = userData.get();
            boolean isPasswordMatch = encoder.matches(changePasswordRequest.getOldPassword(), _user.getPassword());
            if(isPasswordMatch){
                _user.setPassword(encoder.encode(changePasswordRequest.getNewPassword()));
                userRepository.save(_user);
                return ResponseEntity.ok(new MessageResponse("Password changed successfully!"));
            }else{
                return ResponseEntity.badRequest().body(new MessageResponse("Error: Password Mismatch!"));
            }

        }
        else{
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
//        return ResponseEntity.ok(new MessageResponse("Change password successfully!"));

    }

    @PutMapping("/resetPassword/{id}")
    public ResponseEntity<User> resetPassword(@PathVariable("id") long id) {
        System.out.println("resetPassword");
        Optional<User> userData = userRepository.findById(id);
//        String resetPwd = "12345678";
        if(userData.isPresent()){
            User _user = userData.get();
            _user.setPassword(encoder.encode(resetPwd));
            return new ResponseEntity<>(userRepository.save(_user), HttpStatus.OK);
        }else{
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }
}
