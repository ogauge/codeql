#![cfg(test)]
use std::cell::Cell;
use std::path::Path;
use std::rc::Rc;

use yeast::captures::Captures;
use yeast::*;
#[test]
fn test_ruby_multiple_assignment() {


    // We want to convert this
    //
    // x, y, z = e
    //
    // into this
    //
    // __tmp_1 = e
    // x = __tmp_1[0]
    // y = __tmp_1[1]
    // z = __tmp_1[2]

    // Define a desugaring rule, which is a query together with a transformation.

    let fresh_ids = Rc::new(Cell::new(0));

    let query = query!(
            (assignment
                left: (
                    left_assignment_list (@left)*
                )
                right: (@right)
            )
    );
    let transform = move |ast: &mut Ast, mut match_: Captures| {
        let fresh = fresh_ids.get();
        fresh_ids.set(fresh + 1);

        let new_ident = format!("tmp-{}", fresh);
        match_.insert("tmp_lhs", ast.create_token("identifier", new_ident.clone()));
        
        let mut i = 0;
        match_.map_captures_to("left", "assigns", &mut |old_id| {
            let mut local_capture = Captures::new();
            local_capture.insert("lhs", old_id);
            local_capture.insert("tmp", ast.create_token("identifier", new_ident.clone()));
            let index: i32 = i;
            i += 1;
            local_capture.insert("index", ast.create_token("integer", index.to_string()));

            return tree_builder!(
                (assignment
                    left: (identifier (@lhs))
                    right: (
                        element_reference
                            left: (@tmp)
                            right: (integer (@index))
                    )
                )
            )
            .build_tree(ast, &local_capture)
            .unwrap();
        });

        // construct the new tree here maybe
        // captures is probably a HashMap from capture name to AST node
        trees_builder!(
            (assignment
                left: (@tmp_lhs)
                right: (@right)
            )
            (
                @assigns
            )*
        )
        .build_trees(ast, &match_)
        .unwrap()
    };
    
    let rule = Rule::new(query, Box::new(transform));

    let input = "x, y, z = e";

    // Construct the thing that runs our desugaring process
    let runner = Runner::new(tree_sitter_ruby::language(), vec![rule]);

    // Run it on our example
    let (ast, newRootId) = runner.run(input);

    let formattedInput = serde_json::to_string_pretty(&ast.print(&input, 0)).unwrap();
    let formattedOutput = serde_json::to_string_pretty(&ast.print(&input, newRootId)).unwrap();

    println!("before transformation: {}", formattedInput);
    println!("after transformation: {}", formattedOutput);

    // we could create a macro for this
    // let expected_output = ast! {
    //     assignment {
    //         left: identifier { name: "__tmp" },
    //         right: identifier { name: "e" },
    //     },
    //     assignment {
    //         left: identifier { name: "x" },
    //         right: element_reference {
    //             object: identifier { name: "__tmp" },
    //             index: integer(0)
    //         },
    //     },
    //     assignment {
    //         left: identifier { name: "y" },
    //         right: element_reference {
    //             object: identifier { name: "__tmp" },
    //             index: integer(1)
    //         },
    //     },
    //     assignment {
    //         left: identifier { name: "z" },
    //         right: element_reference {
    //             object: identifier { name: "__tmp" },
    //             index: integer(2)
    //         },
    //     },
    // };
    let expected_output = todo!();

    assert_eq!(ast, expected_output);
}

#[test]
fn test_parse_input() {
    let input = std::fs::read_to_string("tests/fixtures/1.rb").unwrap();
    let parsed_expected = std::fs::read_to_string("tests/fixtures/1.parsed.json").unwrap();

    let runner = Runner::new(tree_sitter_ruby::language(), vec![]);
    let (ast, newRootId) = runner.run(&input);
    let parsed_actual = serde_json::to_string_pretty(&ast.print(&input, newRootId)).unwrap();

    assert_eq!(parsed_actual, parsed_expected);
}

#[test]
fn test_query_input() {
    let input = std::fs::read_to_string("tests/fixtures/1.rb").unwrap();
    let rewritten_expected = std::fs::read_to_string("tests/fixtures/1.rewritten.json").unwrap();

    let runner = Runner::new(tree_sitter_ruby::language(), vec![]);
    let (mut ast, root) = runner.run(&input);

    let query = yeast::query::query!(
        program (
            (assignment
                left: (@left)
                right: (@right)
                (@rest)*
            )
        )
    );
    print!("query: {:?}", query);

    let mut matches = Captures::new();
    if query.do_match(&ast, root, &mut matches).unwrap() {
        println!("match: {:?}", matches);
    } else {
        println!("no match");
    }

    let builder = yeast::tree_builder::tree_builder!(
        program (
            (assignment
                left: (@right)
                right: (@left)
                (@rest)*
            )
        )
    );

    let new_id = builder.build_tree(&mut ast, &matches).unwrap();

    let rewritten_actual = serde_json::to_string_pretty(&ast.print(&input, new_id)).unwrap();

    write_expected("tests/fixtures/1.rewritten.json", &rewritten_actual);
    assert_eq!(rewritten_actual, rewritten_expected);
}

/// Useful for updating fixtures
/// ```
/// write_expected("tests/fixtures/1.parsed.json", &parsed_actual);
/// ```
fn write_expected<P: AsRef<Path>>(file: P, content: &str) {
    use std::io::Write;
    std::fs::File::create(file)
        .unwrap()
        .write_all(content.as_bytes())
        .unwrap();
}
