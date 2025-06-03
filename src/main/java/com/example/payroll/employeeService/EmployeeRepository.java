package com.example.payroll.employeeService;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface EmployeeRepository extends JpaRepository<Employee, Long> {

    public Optional<Employee> findByEmail(String email);

      // New method to find employees by name (case-insensitive)
    public List<Employee> findByNameContainingIgnoreCase(String name);
    
    // Alternative: exact match (case-insensitive)
    public Optional<Employee> findByNameIgnoreCase(String name);
}