package com.example.payroll.employeeService;

import com.example.payroll.departmentService.Department;
import com.example.payroll.security.User;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToOne;
import lombok.Data;

@Entity
@Data
public class Employee {

  private @Id @GeneratedValue Long id;
  private String name;
  private String role;
  private String email;

  @ManyToOne
  @JoinColumn(name = "department_id", nullable = false)
  private Department department;

  @OneToOne
  @JoinColumn(name = "user_id", nullable = false)
  private User user;

  public Employee() {
  }
  public Employee(String name, String role, String email) {
    this.name = name;
    this.role = role;
    this.email = email;
  }

}
