package com.example.payroll.departmentService;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import com.example.payroll.employeeService.Employee;
import com.fasterxml.jackson.annotation.JsonIdentityInfo;
import com.fasterxml.jackson.annotation.ObjectIdGenerators;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;

@Entity
@JsonIdentityInfo(generator = ObjectIdGenerators.PropertyGenerator.class, property = "id")
public class Department {
    private @Id @GeneratedValue Long id;
    private String name;
    private String location;

    @OneToMany(mappedBy="department", cascade = CascadeType.ALL)
    private Set<Employee> employees;

    public Department() {}

    public Department(String name, String location) {
        this.name = name;
        this.location = location;
        this.employees = new HashSet<>();
    }

    public Long getId() {
        return this.id;
    }

    public String getName() {
        return this.name;
    }

    public String getLocation() {
        return this.location;
    }

    public Set<Employee> getEmployees() {
        return employees;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public void addEmployee(Employee employee) {
        this.employees.add(employee);
    }

@Override
public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    Department that = (Department) o;
    return id.equals(that.id) && name.equals(that.name) && location.equals(that.location);
}

@Override
public int hashCode() {
    return Objects.hash(id, name, location);
}


    @Override
    public String toString() {
        return "Department{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", location='" + location + '\'' +
                '}';
    }

}
