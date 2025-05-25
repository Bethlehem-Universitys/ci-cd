package com.example.payroll.employeeService;

import lombok.Data;

@Data
public class EmployeeDTO {
    private Long id;
    private String name;
    private String role;
    private String email;
    private String departmentName;   
    private String username;
    private String password; 
}
