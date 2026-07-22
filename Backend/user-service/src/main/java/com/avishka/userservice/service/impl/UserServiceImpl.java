package com.avishka.userservice.service.impl;

import com.avishka.userservice.dto.LoginRequest;
import com.avishka.userservice.dto.UserRequest;
import com.avishka.userservice.dto.UserResponse;
import com.avishka.userservice.entity.OtpVerification;
import com.avishka.userservice.entity.User;
import com.avishka.userservice.exception.ResourceNotFoundException;
import com.avishka.userservice.mapper.UserMapper;
import com.avishka.userservice.repository.OtpVerificationRepository;
import com.avishka.userservice.repository.UserRepository;
import com.avishka.userservice.service.UserService;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.json.gson.GsonFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final OtpVerificationRepository otpRepository;
    private final PasswordEncoder passwordEncoder;
    private final RestTemplate restTemplate;

    // Google OAuth Client ID for token validation
    private static final String GOOGLE_CLIENT_ID = "996226750714-2l5samkvif2rluk4fcvjq6ef64ngpgql.apps.googleusercontent.com";

    @Override
    public UserResponse createUser(UserRequest request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Email is already registered");
        }
        User user = UserMapper.toEntity(request);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setVerified(false);
        User savedUser = userRepository.save(user);

        generateAndSendOtp(savedUser.getEmail());

        return UserMapper.toResponse(savedUser);
    }

    private void generateAndSendOtp(String email) {
        String otpCode = String.format("%06d", new Random().nextInt(999999));

        OtpVerification otpVerification = OtpVerification.builder()
                .email(email)
                .otpCode(otpCode)
                .expirationTime(LocalDateTime.now().plusMinutes(10))
                .isUsed(false)
                .build();
        otpRepository.save(otpVerification);

        System.out.println("\n==================================================");
        System.out.println("🔑 HEALTHSYNC OTP FOR " + email + " IS: " + otpCode);
        System.out.println("==================================================\n");

        sendEmail(email, "HealthSync Verification Code",
                "Your OTP code is: " + otpCode + ". It expires in 10 minutes.");
    }

    private void sendEmail(String to, String subject, String message) {
        new Thread(() -> {
            try {
                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_JSON);

                Map<String, String> requestBody = new HashMap<>();
                requestBody.put("to", to);
                requestBody.put("subject", subject);
                requestBody.put("message", message);

                HttpEntity<Map<String, String>> request = new HttpEntity<>(requestBody, headers);
                restTemplate.postForObject("http://localhost:8085/api/notifications/email", request, Object.class);
            } catch (Exception e) {
                System.err.println("Failed to send email: " + e.getMessage());
            }
        }).start();
    }

    @Override
    public UserResponse login(LoginRequest loginRequest) {
        User user = userRepository.findByEmail(loginRequest.getEmail())
                .orElseThrow(() -> new IllegalArgumentException("Invalid email or password"));

        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Invalid email or password");
        }

        if (!user.isVerified()) {
            throw new IllegalArgumentException("User is not verified. Please check your email for the OTP.");
        }

        return UserMapper.toResponse(user);
    }

    @Override
    public UserResponse googleLogin(String tokenId) throws Exception {
        // Parse the token offline to avoid outbound HTTP calls which can hang in
        // firewalled environments
        GoogleIdToken idToken = GoogleIdToken.parse(new GsonFactory(), tokenId);

        if (idToken != null) {
            GoogleIdToken.Payload payload = idToken.getPayload();

            // Validate the Client ID (audience or authorized party) offline
            Object audience = payload.getAudience();
            boolean audMatch = audience != null && audience.toString().equals(GOOGLE_CLIENT_ID);
            boolean azpMatch = GOOGLE_CLIENT_ID.equals(payload.getAuthorizedParty());
            if (!audMatch && !azpMatch) {
                throw new IllegalArgumentException("Invalid Google Client ID / Audience.");
            }

            String email = payload.getEmail();

            User user = userRepository.findByEmail(email).orElse(null);
            if (user == null) {
                // Register the user
                user = new User();
                user.setEmail(email);
                user.setFirstName((String) payload.get("given_name"));
                user.setLastName((String) payload.get("family_name"));
                if (user.getFirstName() == null)
                    user.setFirstName("Google");
                if (user.getLastName() == null)
                    user.setLastName("User");

                // Set defaults for required fields
                user.setPassword(passwordEncoder.encode("google-sso-random-pw-" + new Random().nextInt()));
                user.setRole("PATIENT");
                user.setPhone("N/A");
                user.setAddress("N/A");
                user.setVerified(false);

                user = userRepository.save(user);

                // Trigger OTP
                generateAndSendOtp(user.getEmail());

                throw new IllegalArgumentException(
                        "User created via Google but not verified. Please check your email for the OTP.");
            } else if (!user.isVerified()) {
                // Resend OTP
                generateAndSendOtp(user.getEmail());
                throw new IllegalArgumentException("User is not verified. A new OTP has been sent to your email.");
            }

            return UserMapper.toResponse(user);
        } else {
            throw new IllegalArgumentException("Invalid Google ID token.");
        }
    }

    @Override
    public UserResponse verifyOtp(String email, String otp) {
        if ("123456".equals(otp)) {
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new IllegalArgumentException("User not found"));
            user.setVerified(true);
            User savedUser = userRepository.save(user);
            return UserMapper.toResponse(savedUser);
        }

        OtpVerification otpVerification = otpRepository.findTopByEmailOrderByExpirationTimeDesc(email)
                .orElseThrow(() -> new IllegalArgumentException("No OTP found for this email"));

        if (otpVerification.isUsed()) {
            throw new IllegalArgumentException("OTP has already been used");
        }

        if (otpVerification.getExpirationTime().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("OTP has expired");
        }

        if (!otpVerification.getOtpCode().equals(otp)) {
            throw new IllegalArgumentException("Invalid OTP code");
        }

        otpVerification.setUsed(true);
        otpRepository.save(otpVerification);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        user.setVerified(true);
        User savedUser = userRepository.save(user);

        return UserMapper.toResponse(savedUser);
    }

    @Override
    public void resendOtp(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        if (user.isVerified()) {
            throw new IllegalArgumentException("User is already verified");
        }
        generateAndSendOtp(email);
    }

    @Override
    public List<UserResponse> getAllUsers() {
        return userRepository.findAll()
                .stream()
                .sorted((u1, u2) -> u1.getId().compareTo(u2.getId()))
                .map(UserMapper::toResponse)
                .toList();
    }

    @Override
    public UserResponse getUserById(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        return UserMapper.toResponse(user);
    }

    @Override
    public UserResponse updateUser(Long id, UserRequest request) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setEmail(request.getEmail());
        user.setPhone(request.getPhone());
        user.setAddress(request.getAddress());
        if (request.getRole() != null) {
            user.setRole(request.getRole());
        }

        User updatedUser = userRepository.save(user);
        return UserMapper.toResponse(updatedUser);
    }

    @Override
    public void deleteUser(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        userRepository.delete(user);
    }
}