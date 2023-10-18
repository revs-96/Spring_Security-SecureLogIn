package com.SpringSecurity.JWT.controller;

import com.SpringSecurity.JWT.model.TokenReqRes;
import com.SpringSecurity.JWT.model.Users;
import com.SpringSecurity.JWT.repository.UserRepository;
import com.SpringSecurity.JWT.utils.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping
public class OurController {

    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @PostMapping("/register")
    public ResponseEntity<Object> registerUser(@RequestBody Users user){
        String hashedPassword = bCryptPasswordEncoder.encode(user.getPassword());
        user.setPassword(hashedPassword);
        ;
        if (userRepository.save(user).getId()>0){
            return ResponseEntity.ok("User Was Saved");
        }
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("User Not Saved, Internal Server Error. Please Try Again");
    }

    @PostMapping("/generate-token")
    public ResponseEntity<Object> generateToken(@RequestBody TokenReqRes tokenReqRes){
        Users databaseUser = userRepository.findByUsername(tokenReqRes.getUsername());
        if (databaseUser == null){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Sorry, User Does Not Exist");
        }
        if (new BCryptPasswordEncoder().matches(tokenReqRes.getPassword(), databaseUser.getPassword())){
            String token = jwtTokenUtil.generateToken(tokenReqRes.getUsername());
            tokenReqRes.setToken(token);
            tokenReqRes.setExpirationTime("60 Sec");
            return ResponseEntity.ok(tokenReqRes);
        }else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Password Doesn't Match. Verify");
        }
    }
    @PostMapping("/validate-token")
    public ResponseEntity<Object> validateToken(@RequestBody TokenReqRes tokenReqRes){
        return ResponseEntity.ok(jwtTokenUtil.validateToken(tokenReqRes.getToken()));
    }

    @GetMapping("/get-fruits")
    public  ResponseEntity<Object> getAllFruits(@RequestHeader(value = "Authorization", required = false) String token){
        if (token == null){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token Is required to Proceed");
        }else{
            String realToken = token.substring(7);
            String tokenCheckResult = jwtTokenUtil.validateToken(realToken);
            if (tokenCheckResult.equalsIgnoreCase("valid")){
                List<String> fruits = List.of("Mango", "Banana", "Orange","Watermelon","Grapes", "Apple", "Berries");
                return new ResponseEntity<>(fruits, HttpStatus.OK);
            }else{
                return  ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized dur to: " + tokenCheckResult);
            }
        }
    }


}
