package com.secure.notes.models;

import jakarta.persistence.*;
import lombok.Data;


@Entity
@Data
public class Note {


    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

//  Lob is used for storing long notes content
    @Lob
    private String content;

    private String ownerUsername;
}
