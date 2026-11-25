use std::hint::black_box;

#[inline(never)]
fn collatz_steps(mut n: u64) -> u64 {
    let mut steps = 0u64;
    while n != 1 {
        n = if n % 2 == 0 { n / 2 } else { n * 3 + 1 };
        steps += 1;
    }
    steps
}

#[inline(never)]
fn classify(x: i32) -> &'static str {
    if x <= 0 {
        "non-positive"
    } else if x < 10 {
        "small"
    } else if x < 100 {
        "medium"
    } else if x < 1000 {
        "large"
    } else {
        "huge"
    }
}

#[inline(never)]
fn nested_loops(n: usize) -> usize {
    let mut total = 0usize;
    for i in 0..n {
        for j in 0..n {
            if i != j {
                total += i * j;
            }
            if total > 10000 {
                break;
            }
        }
        if total > 10000 {
            break;
        }
    }
    total
}

#[inline(never)]
fn day_name(x: u32) -> &'static str {
    match x {
        0 => "Sunday",
        1 => "Monday",
        2 => "Tuesday",
        3 => "Wednesday",
        4 => "Thursday",
        5 => "Friday",
        6 => "Saturday",
        _ => "Unknown",
    }
}

#[inline(never)]
async fn async_collatz_steps(mut n: u64) -> u64 {
    let mut steps = 0u64;
    while n != 1 {
        n = if n % 2 == 0 { n / 2 } else { n * 3 + 1 };
        steps += 1;
        tokio::task::yield_now().await;
    }
    steps
}

#[inline(never)]
async fn async_complex_flow(x: i32) -> &'static str {
    let res = classify(x);
    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    res
}

#[inline(never)]
fn check_leak() {
    let secret = black_box("Bearer sk-live-0123456789abcdefABCDEF");
    assert_eq!(secret.len(), 37, "RemoveLeak 破坏了字符串常量长度！");
    assert!(
        secret.starts_with("Bearer "),
        "RemoveLeak 破坏了非敏感前缀！"
    );
    assert!(!secret.contains("sk-live-"), "敏感密钥 sk-live- 未被擦除！");

    let src_file = black_box(file!());
    assert!(
        !src_file.contains("main.rs"),
        "源码路径 src/main.rs 未被擦除！"
    );
    println!("[OK] RemoveLeak 内存自检通过: secret={secret}, file={src_file}");
}

async fn check_control_flow() {
    assert_eq!(collatz_steps(black_box(27)), 111);
    assert_eq!(classify(black_box(50)), "medium");
    assert!(nested_loops(black_box(50)) > 0);
    assert_eq!(day_name(black_box(3)), "Wednesday");
    assert_eq!(day_name(black_box(99)), "Unknown");

    let async_c = async_collatz_steps(black_box(27)).await;
    assert_eq!(async_c, 111);

    let t1 = tokio::spawn(async { async_collatz_steps(9).await });
    let t2 = tokio::spawn(async { async_complex_flow(50).await });
    let (r1, r2) = tokio::join!(t1, t2);
    assert_eq!(r1.expect("Task 1 failed"), 19);
    assert_eq!(r2.expect("Task 2 failed"), "medium");
    println!("[OK] 同步与 Tokio 异步控制流自检通过");
}

#[inline(never)]
fn check_bo() {
    let secret = black_box("Bearer sk-live-bo-e2e-0123456789abcdef");
    assert_eq!(secret.len(), 38, "BytesObfuscation 破坏了字符串长度！");
    assert!(
        secret.starts_with("Bearer "),
        "BytesObfuscation 运行时解密前缀错误！"
    );
    assert!(
        secret.ends_with("-bo-e2e-0123456789abcdef"),
        "BytesObfuscation 运行时解密后缀错误！"
    );
    assert_eq!(
        &secret.as_bytes()[7..15],
        b"sk-live-",
        "BytesObfuscation 运行时解密核心内容错误！"
    );
    println!("[OK] BytesObfuscation 运行时惰性解密自检通过: secret={secret}");
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--trigger-panic") {
        let arr = black_box([10u32, 20, 30]);
        println!("Unreachable: {}", arr[black_box(99)]);
        return;
    }

    if args.iter().any(|a| a == "--check-leak") {
        check_leak();
    }

    if args.iter().any(|a| a == "--check-flow") || args.len() == 1 {
        check_control_flow().await;
    }

    if args.iter().any(|a| a == "--check-bo") {
        check_bo();
    }
}
