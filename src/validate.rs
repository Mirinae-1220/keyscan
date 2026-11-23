use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Validator {
    Luhn,
    KrBrn,
    KrRrn,
}

impl Validator {
    pub fn check(self, value: &str) -> bool {
        let digits: Vec<u32> = value.chars().filter_map(|c| c.to_digit(10)).collect();
        match self {
            Validator::Luhn => luhn(&digits),
            Validator::KrBrn => kr_brn(&digits),
            Validator::KrRrn => kr_rrn(&digits),
        }
    }
}

fn luhn(d: &[u32]) -> bool {
    if d.len() < 12 || d.iter().all(|&x| x == d[0]) {
        return false;
    }
    let sum: u32 = d
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &x)| {
            if i % 2 == 1 {
                let y = x * 2;
                if y > 9 { y - 9 } else { y }
            } else {
                x
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

fn kr_brn(d: &[u32]) -> bool {
    if d.len() != 10 || d.iter().all(|&x| x == d[0]) {
        return false;
    }
    const W: [u32; 9] = [1, 3, 7, 1, 3, 7, 1, 3, 5];
    let mut sum: u32 = d.iter().zip(W).map(|(&x, w)| x * w).sum();
    sum += d[8] * 5 / 10;
    (10 - sum % 10) % 10 == d[9]
}

// 2020년 10월부터 뒷자리 지역번호·검증번호가 임의 숫자로 바뀌어 옛 검증 공식이 새 번호를 떨어뜨린다.
// 그래서 생년월일이 실제 날짜인지와 성별 자리만 본다.
fn kr_rrn(d: &[u32]) -> bool {
    if d.len() != 13 {
        return false;
    }
    let yy = d[0] * 10 + d[1];
    let mm = d[2] * 10 + d[3];
    let dd = d[4] * 10 + d[5];
    let year = match d[6] {
        1 | 2 | 5 | 6 => 1900 + yy,
        3 | 4 | 7 | 8 => 2000 + yy,
        9 | 0 => 1800 + yy,
        _ => return false,
    };
    (1..=12).contains(&mm) && dd >= 1 && dd <= days_in_month(year, mm)
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400) => {
            29
        }
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_check() {
        assert!(Validator::Luhn.check(concat!("4111-1111", "-1111-1111")));
        assert!(Validator::Luhn.check(concat!("5555 5555", " 5555 4444")));
        assert!(!Validator::Luhn.check(concat!("4111-1111", "-1111-1112")));
        assert!(!Validator::Luhn.check("0000-0000-0000-0000"));
    }

    #[test]
    fn brn_check() {
        assert!(Validator::KrBrn.check(concat!("123-45", "-67891")));
        assert!(!Validator::KrBrn.check(concat!("123-45", "-67890")));
        assert!(!Validator::KrBrn.check("000-00-00000"));
    }

    #[test]
    fn rrn_check() {
        assert!(Validator::KrRrn.check(concat!("900101", "-1234567")));
        assert!(Validator::KrRrn.check(concat!("040229", "-3234567")));
        assert!(Validator::KrRrn.check(concat!("850315", "-6234567")));
        assert!(!Validator::KrRrn.check("030229-3234567"));
        assert!(!Validator::KrRrn.check("901301-1234567"));
        assert!(!Validator::KrRrn.check("900132-2234567"));
    }
}
