package com.example.payroll.employeeService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.hateoas.CollectionModel;
import org.springframework.hateoas.EntityModel;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;

@RestController
class EmployeeController {

  @Autowired
  private EmployeeService employeeService;

  @Operation(summary = "Get all employees", description = "Fetches a list of all employees.")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Successfully retrieved users")
    })
  @GetMapping("/employees")
  CollectionModel<EntityModel<EmployeeDTO>> all() {
    return employeeService.findAll();
  }

  @PostMapping("/employees")
  ResponseEntity<?> newEmployee(@RequestBody EmployeeDTO newEmployee) {
    return employeeService.newEmployee(newEmployee);   
  }
  
  @GetMapping("/employees/{id}")
  ResponseEntity<?> one(@PathVariable Long id) {
      return employeeService.findById(id);    
  }

  @GetMapping("/employees/email/{email}")
  EntityModel<EmployeeDTO> getEmployeeByEmail(@PathVariable String email) {
    return employeeService.findByEmail(email);
  }

  @PutMapping("/employees/{id}")
  ResponseEntity<?> replaceEmployee(@RequestBody EmployeeDTO newEmployee, @PathVariable Long id) {
    return ResponseEntity.ok(employeeService.save(newEmployee, id));    
  }

  @DeleteMapping("/employees/{id}")
  ResponseEntity<?> deleteEmployee(@PathVariable Long id) {
    return employeeService.deleteById(id);
  }
}