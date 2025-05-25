package com.example.payroll;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.example.payroll.departmentService.Department;
import com.example.payroll.departmentService.DepartmentRepository;
import com.example.payroll.employeeService.Employee;
import com.example.payroll.employeeService.EmployeeRepository;
import com.example.payroll.security.User;
import com.example.payroll.security.UserRepository;

@Configuration
class LoadDatabase {
  @Autowired
  private PasswordEncoder passwordEncoder;

  private static final Logger log = LoggerFactory.getLogger(LoadDatabase.class);

  @Bean
  CommandLineRunner initDatabase(EmployeeRepository repository, DepartmentRepository departmentRepository, UserRepository userRepository) {

    Department department = new Department("IT", "Bethlehem");
    Department department2 = new Department("HR", "Ramallah");
    departmentRepository.save(department);
    departmentRepository.save(department2);

    User user = new User("Bilbo@gmail.com", passwordEncoder.encode("bilbo"), "ROLE_ADMIN");
    userRepository.save(user);
    User user2 = new User("Frodo@gmail.com", passwordEncoder.encode("frodo"), "ROLE_USER");
    userRepository.save(user2);
    
    Employee employee = new Employee("Bilbo Baggins", "burglar", "bilbo@email.com");
    employee.setUser(user);
    employee.setDepartment(department);
    department.addEmployee(employee);
    
    Employee employee2 = new Employee("Frodo Baggins", "thief", "frodo@email.com");
    employee2.setUser(user2);
    employee2.setDepartment(department2);
    department2.addEmployee(employee2);


    return args -> {
      log.info("Preloading " + repository.save(employee));
      log.info("Preloading " + repository.save(employee2));
    };
  }
}