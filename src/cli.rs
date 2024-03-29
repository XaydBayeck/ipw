use std::{num::ParseIntError, path::PathBuf};

use clap::{Parser, Subcommand};

use crate::head::Protocol;

/// 发送、捕获IP报文并进行过滤与分析。
#[derive(Debug, Parser)]
#[command(version, about, long_about=None)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// 发送IP数据报报文
    Send {
        /// 目的MAC地址
        #[arg(value_parser = ipp, long, short)]
        dhost: [u8; 6],
        /// 目的IP地址
        #[arg(value_parser = ipp, long, short)]
        destip: [u8; 4],
        /// 协议类型。可选值有 TCP、UDP、ICMP 以及十进制的一个字节长数字
        #[arg(value_parser = protocolp, long, short)]
        protocol: Protocol,
        /// 解析数据的进制
        #[arg(long, short)]
        radix: u32,
        /// 报文数据
        #[arg(long, short)]
        text: Option<String>,
        /// 报文数据文件路径
        #[arg(long, short)]
        file: Option<PathBuf>,
    },
    /// 分析本机接收的IP报文类型和数量
    Analyz,
    /// 过滤显示接收到的IP报文及其首部信息
    Filter {
        #[arg(value_parser = ipparser::<6, 16>, long)]
        src_mac: Option<[u8; 6]>,
        #[arg(value_parser = ipparser::<6, 16>, long)]
        dst_mac: Option<[u8; 6]>,
        #[arg(value_parser = ipp, long, short)]
        shost: Option<[u8; 4]>,
        #[arg(value_parser = ipp, long, short)]
        dhost: Option<[u8; 4]>,
        #[arg(long, short)]
        log: bool,
    },
}

fn protocolp(inputs: &str) -> Result<Protocol, ParseIntError> {
    Ok(match inputs {
        "TCP" => Protocol::TCP,
        "UDP" => Protocol::UDP,
        "ICMP" => Protocol::ICMP,
        _ => Protocol::Other(u8::from_str_radix(inputs, 10)?),
    })
}

fn ipp(inputs: &str) -> Result<[u8; 4], ParseIntError> {
    if inputs == "localhost" {
        Ok([127, 0, 0, 1])
    } else {
        ipparser::<4, 10>(inputs)
    }
}

fn ipparser<const S: usize, const R: u32>(inputs: &str) -> Result<[u8; S], ParseIntError> {
    inputs
        .split('.')
        .enumerate()
        .try_fold([0; S], |mut result, (idx, num)| {
            let num = u8::from_str_radix(num, R)?;
            result[idx] = num;
            Ok(result)
        })
}
