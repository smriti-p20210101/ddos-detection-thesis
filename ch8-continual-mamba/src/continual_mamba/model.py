from __future__ import annotations

import math

import torch
import torch.nn as nn
import torch.nn.functional as F


class SelectiveSSMBlock(nn.Module):
    def __init__(self, d_model: int, dropout: float) -> None:
        super().__init__()
        self.in_proj = nn.Linear(d_model, d_model)
        self.delta_proj = nn.Linear(d_model, d_model)
        self.gate_proj = nn.Linear(d_model, d_model)
        self.out_proj = nn.Linear(d_model, d_model)
        self.norm = nn.LayerNorm(d_model)
        self.dropout = nn.Dropout(dropout)
        self.a_log = nn.Parameter(torch.zeros(d_model))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: [B, T, D]
        bsz, seq_len, d_model = x.shape
        h = torch.zeros((bsz, d_model), dtype=x.dtype, device=x.device)
        outputs = []

        a = -torch.exp(self.a_log).unsqueeze(0)  # [1, D]
        for t in range(seq_len):
            xt = x[:, t, :]
            u = self.in_proj(xt)
            delta = F.softplus(self.delta_proj(xt))
            gate = torch.sigmoid(self.gate_proj(xt))
            h = (1.0 + delta * a) * h + delta * gate * u
            yt = self.out_proj(h)
            outputs.append(yt.unsqueeze(1))

        y = torch.cat(outputs, dim=1)
        y = self.dropout(y)
        return self.norm(x + y)


class KANLinear(nn.Module):
    """KAN-inspired layer with learnable radial basis activations."""

    def __init__(self, in_dim: int, out_dim: int, grid_size: int) -> None:
        super().__init__()
        self.in_dim = in_dim
        self.out_dim = out_dim
        self.grid_size = grid_size

        centers = torch.linspace(-2.5, 2.5, grid_size).unsqueeze(0).repeat(in_dim, 1)
        self.centers = nn.Parameter(centers)
        self.log_widths = nn.Parameter(torch.zeros(in_dim, grid_size))
        self.weight = nn.Parameter(torch.randn(out_dim, in_dim, grid_size) * 0.02)
        self.base = nn.Linear(in_dim, out_dim)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: [B, I]
        x_exp = x.unsqueeze(-1)  # [B, I, 1]
        widths = F.softplus(self.log_widths) + 1e-4  # [I, K]
        phi = torch.exp(-((x_exp - self.centers.unsqueeze(0)) / widths.unsqueeze(0)) ** 2)
        kan_out = torch.einsum("bik,oik->bo", phi, self.weight)
        return kan_out + self.base(x)


class KANHead(nn.Module):
    def __init__(self, in_dim: int, hidden_dim: int, out_dim: int, grid_size: int, dropout: float) -> None:
        super().__init__()
        self.fc1 = KANLinear(in_dim, hidden_dim, grid_size)
        self.fc2 = KANLinear(hidden_dim, out_dim, grid_size)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = F.silu(self.fc1(x))
        x = self.dropout(x)
        return self.fc2(x)


class MLPHead(nn.Module):
    def __init__(self, in_dim: int, hidden_dim: int, out_dim: int, dropout: float) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, hidden_dim),
            nn.SiLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, out_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class ContinualMamba(nn.Module):
    def __init__(
        self,
        input_dim: int,
        num_classes: int,
        d_model: int,
        seq_len: int,
        ssm_layers: int,
        kan_hidden: int,
        kan_grid: int,
        dropout: float,
        variant: str = "mamba_kan",
    ) -> None:
        super().__init__()
        self.input_dim = input_dim
        self.seq_len = seq_len
        self.variant = variant
        token_dim = math.ceil(input_dim / seq_len)
        self.padded_dim = token_dim * seq_len
        self.token_dim = token_dim

        self.input_proj = nn.Linear(token_dim, d_model)
        self.pos_emb = nn.Parameter(torch.zeros(1, seq_len, d_model))
        self.use_ssm = variant in {"mamba_kan", "mamba_mlp"}
        if self.use_ssm:
            self.ssm = nn.ModuleList([SelectiveSSMBlock(d_model=d_model, dropout=dropout) for _ in range(ssm_layers)])
        else:
            self.ffn = nn.Sequential(
                nn.Linear(d_model, d_model),
                nn.SiLU(),
                nn.Dropout(dropout),
                nn.Linear(d_model, d_model),
            )
        self.norm = nn.LayerNorm(d_model)
        if variant in {"mamba_kan", "mlp_kan"}:
            self.head = KANHead(
                in_dim=d_model,
                hidden_dim=kan_hidden,
                out_dim=num_classes,
                grid_size=kan_grid,
                dropout=dropout,
            )
        else:
            self.head = MLPHead(
                in_dim=d_model,
                hidden_dim=kan_hidden,
                out_dim=num_classes,
                dropout=dropout,
            )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: [B, F]
        if x.shape[1] < self.padded_dim:
            pad = self.padded_dim - x.shape[1]
            x = F.pad(x, (0, pad))
        elif x.shape[1] > self.padded_dim:
            x = x[:, : self.padded_dim]

        x = x.view(x.size(0), self.seq_len, self.token_dim)
        x = self.input_proj(x) + self.pos_emb
        if self.use_ssm:
            for layer in self.ssm:
                x = layer(x)
        else:
            x = self.ffn(x)
        x = self.norm(x).mean(dim=1)
        return self.head(x)
