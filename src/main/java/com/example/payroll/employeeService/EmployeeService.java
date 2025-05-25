package com.example.payroll.employeeService;

import org.springframework.hateoas.CollectionModel;
import org.springframework.hateoas.EntityModel;
import org.springframework.http.ResponseEntity;

public interface EmployeeService {
    CollectionModel<EntityModel<EmployeeDTO>> findAll(); 
    ResponseEntity<?> newEmployee(EmployeeDTO newEmployee);
    ResponseEntity<?> findById(Long id);
    EntityModel<EmployeeDTO> findByEmail(String email);
    ResponseEntity<?> save(EmployeeDTO employee, Long id); 
    ResponseEntity<?> deleteById(Long id); 
}
