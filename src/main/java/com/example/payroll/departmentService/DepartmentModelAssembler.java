package com.example.payroll.departmentService;

import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.*;

import org.springframework.hateoas.EntityModel;
import org.springframework.hateoas.server.RepresentationModelAssembler;
import org.springframework.stereotype.Component;

@Component
class DepartmentModelAssembler implements RepresentationModelAssembler<Department, EntityModel<Department>> {

  @Override
  public EntityModel<Department> toModel(Department department) {

    return EntityModel.of(department, //
        linkTo(methodOn(DepartmentController.class).one(department.getId())).withSelfRel(),
        linkTo(methodOn(DepartmentController.class).all()).withRel("departments"));
  }
}
