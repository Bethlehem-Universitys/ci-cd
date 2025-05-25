package com.example.payroll.employeeService;

import com.example.payroll.departmentService.Department;

public class EmployeeMapper {

    public static Employee toEntity(EmployeeDTO employeeDTO, Department dep) {
        Employee employee = new Employee();
        employee.setName(employeeDTO.getName());
        employee.setRole(employeeDTO.getRole());
        employee.setEmail(employeeDTO.getEmail());
        employee.setDepartment(dep);
        return employee;
    }

    public static EmployeeDTO toDTO(Employee employee) {
        EmployeeDTO employeeDTO = new EmployeeDTO();
        employeeDTO.setId(employee.getId());
        employeeDTO.setName(employee.getName());
        employeeDTO.setRole(employee.getRole());
        employeeDTO.setEmail(employee.getEmail());
        employeeDTO.setDepartmentName(employee.getDepartment().getName());
        return employeeDTO;
    }
}
