package com.example.todo.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.todo.dto.ResponseDTO;
import com.example.todo.dto.UserDTO;
import com.example.todo.model.UserEntity;
import com.example.todo.security.TokenProvider;
import com.example.todo.service.UserService;

import lombok.extern.slf4j.Slf4j;

/*@CrossOrigin(origins = "*")*/
@Slf4j
@RestController
@RequestMapping("/auth")

public class UserController {
	@Autowired
	private UserService userService;
	
	@Autowired
	private TokenProvider tokenProvider;
	
	private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
	
	@PostMapping("/signup")
	public ResponseEntity<?>registerUser(@RequestBody UserDTO userDTO){
		try {
			UserEntity user = UserEntity.builder()
					.email(userDTO.getEmail())
					.username(userDTO.getEmail())
					.password(passwordEncoder.encode(userDTO.getPassword()))
					.build();
			
			UserEntity registeredUser = userService.create(user);
			UserDTO responseUserDTO = userDTO.builder()
					.email(registeredUser.getEmail())
					.id(registeredUser.getId())
					.username(registeredUser.getUsername())
					.build();
			return ResponseEntity.ok().body(responseUserDTO);
		}catch(Exception e) {
			ResponseDTO responseDTO = 
					ResponseDTO.builder().error(e.getMessage()).build();
			return ResponseEntity.badRequest().body(responseDTO);
		}
	}

	@PostMapping("/signin")
	public ResponseEntity<?>authenticate(@RequestBody UserDTO userDTO){
		UserEntity user = userService.getByCredentials(userDTO.getEmail(), userDTO.getPassword(), passwordEncoder);
		
		if(user !=null) {
			final String token = tokenProvider.create(user);
			final UserDTO responseUserDTO = UserDTO.builder()
					.email(user.getEmail())
					.id(user.getId())
					.token(token)
					.build();
			
			return ResponseEntity.ok().body(responseUserDTO);
		}else {
			ResponseDTO responseDTO = ResponseDTO.builder()
					.error("Login failed")
					.build();
			return ResponseEntity.badRequest().body(responseDTO);
		}
	}

	
    @PostMapping("/delaccount")
    public ResponseEntity<?> deleteAccount(@RequestBody UserDTO userDTO) {
        try {
            String userId = userDTO.getId();
            userService.delete(userId);
            return ResponseEntity.ok().body(Map.of("message", "User deleted successfully"));
        } catch (Exception e) {
            ResponseDTO responseDTO = ResponseDTO.builder().error(e.getMessage()).build();
            return ResponseEntity.badRequest().body(responseDTO);
        }
    }

	

    
	/*
	 * @PostMapping("/delaccount") public ResponseEntity<?>
	 * deleteAccount(@AuthenticationPrincipal String userId, @RequestBody UserDTO
	 * userDTO){ try { UserEntity userEntity = UserDTO.toEntity(userDTO);
	 * userEntity.setId(userId); // 사용자 ID 설정
	 * 
	 * // 서비스 계층을 통해 사용자 삭제 UserEntity deletedUser = userService.delete(userEntity);
	 * 
	 * UserDTO deletedUserDTO = UserDTO.fromEntity(deletedUser);
	 * 
	 * ResponseDTO<UserDTO> response = ResponseDTO.<UserDTO>builder()
	 * .data(Collections.singletonList(deletedUserDTO)) .build(); return
	 * ResponseEntity.ok().body(response); } catch(Exception e) {
	 * 
	 * String error = e.getMessage(); ResponseDTO<UserDTO> response =
	 * ResponseDTO.<UserDTO>builder() .error(error) .build(); return
	 * ResponseEntity.badRequest().body(response); } }
	 */
    

}
