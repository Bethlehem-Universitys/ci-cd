package com.example.payroll.departmentService;


import java.util.List;
import java.util.stream.Collectors;

import org.springframework.hateoas.CollectionModel;
import org.springframework.hateoas.EntityModel;
import org.springframework.hateoas.IanaLinkRelations;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.payroll.exceptions.ResourceNotFoundException;

import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.*;

@RestController
public class DepartmentController {

    private final DepartmentRepository repository;
    private final DepartmentModelAssembler assembler;
  
    DepartmentController(DepartmentRepository repository, DepartmentModelAssembler assembler) {
  
      this.repository = repository;
      this.assembler = assembler;
    }
  
  
    // Aggregate root
    // tag::get-aggregate-root[]
    @GetMapping("/departments")
    CollectionModel<EntityModel<Department>> all() {
    
      List<EntityModel<Department>> departments = repository.findAll().stream() //
          .map(assembler::toModel) //
          .collect(Collectors.toList());
    
      return CollectionModel.of(departments, linkTo(methodOn(DepartmentController.class).all()).withSelfRel());
    }
    // end::get-aggregate-root[]
  
   @PostMapping("/departments")
  ResponseEntity<?> newDepartment(@RequestBody Department newDepartment) {
  
    EntityModel<Department> entityModel = assembler.toModel(repository.save(newDepartment));
  
    return ResponseEntity //
        .created(entityModel.getRequiredLink(IanaLinkRelations.SELF).toUri()) //
        .body(entityModel);
  }
  
    // Single item
    
    @GetMapping("/departments/{id}")
    EntityModel<Department> one(@PathVariable Long id) {
    
      Department Department = repository.findById(id) //
          .orElseThrow(() -> new ResourceNotFoundException("Department with ID "+id+" not found"));
    
          return assembler.toModel(Department);
    }

  
    @PutMapping("/departments/{id}")
    ResponseEntity<?> replaceDepartment(@RequestBody Department newDepartment, @PathVariable Long id) {
    
      Department updatedDepartment = repository.findById(id) //
          .map(department -> {
            department.setName(newDepartment.getName());
            department.setLocation(newDepartment.getLocation());
            return repository.save(department);
          }) //
          .orElseGet(() -> {
            return repository.save(newDepartment);
          });
    
      EntityModel<Department> entityModel = assembler.toModel(updatedDepartment);
    
      return ResponseEntity //
          .created(entityModel.getRequiredLink(IanaLinkRelations.SELF).toUri()) //
          .body(entityModel);
    }
  
  @DeleteMapping("/departments/{id}")
  ResponseEntity<?> deleteDepartment(@PathVariable Long id) {
  
    repository.deleteById(id);
  
    return ResponseEntity.noContent().build();
  }
  }